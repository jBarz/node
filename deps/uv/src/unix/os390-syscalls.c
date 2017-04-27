/* Copyright libuv project contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */


#include "os390-syscalls.h"
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <search.h>
#include <limits.h>

#define CW_CONDVAR 32

#pragma linkage(BPX4CTW, OS)
#pragma linkage(BPX1CTW, OS)

static int number_of_epolls;
static QUEUE global_epoll_queue;
static uv_mutex_t global_epoll_lock;
static uv_once_t once = UV_ONCE_INIT;

int scandir(const char* maindir, struct dirent*** namelist,
            int (*filter)(const struct dirent*),
            int (*compar)(const struct dirent**,
            const struct dirent **)) {
  struct dirent** nl;
  struct dirent* dirent;
  unsigned count;
  size_t allocated;
  DIR* mdir;

  nl = NULL;
  count = 0;
  allocated = 0;
  mdir = opendir(maindir);
  if (!mdir)
    return -1;

  while (1) {
    dirent = readdir(mdir);
    if (!dirent)
      break;
    if (!filter || filter(dirent)) {
      struct dirent* copy;
      copy = uv__malloc(sizeof(*copy));
      if (!copy) {
        while (count) {
          dirent = nl[--count];
          uv__free(dirent);
        }
        uv__free(nl);
        closedir(mdir);
        errno = ENOMEM;
        return -1;
      }
      memcpy(copy, dirent, sizeof(*copy));

      nl = uv__realloc(nl, sizeof(*copy) * (count + 1));
      nl[count++] = copy;
    }
  }

  qsort(nl, count, sizeof(struct dirent *),
       (int (*)(const void *, const void *)) compar);

  closedir(mdir);

  *namelist = nl;
  return count;
}


static unsigned int next_power_of_two(unsigned int val) {
  val -= 1;
  val |= val >> 1;
  val |= val >> 2;
  val |= val >> 4;
  val |= val >> 8;
  val |= val >> 16;
  val += 1;
  return val;
}


static void maybe_resize(uv__os390_epoll* lst, unsigned int len) {
  unsigned int newsize;
  unsigned int i;
  struct pollfd* newlst;

  if (len <= lst->size)
    return;

  newsize = next_power_of_two(len);
  newlst = uv__realloc(lst->items, newsize * sizeof(lst->items[0]));

  if (newlst == NULL)
    abort();
  for (i = lst->size; i < newsize; ++i)
    newlst[i].fd = -1;

  lst->items = newlst;
  lst->size = newsize;
}


static void epoll_init() {
  QUEUE_INIT(&global_epoll_queue);
  if (uv_mutex_init(&global_epoll_lock))
    abort();
}


uv__os390_epoll* epoll_create1(int flags) {
  uv__os390_epoll* lst;

  uv_once(&once, epoll_init);
  uv_mutex_lock(&global_epoll_lock);
  lst = uv__malloc(sizeof(*lst));
  if (lst == -1)
    return NULL;
  QUEUE_INSERT_TAIL(&global_epoll_queue, &lst->member);
  uv_mutex_unlock(&global_epoll_lock);

  /* initialize list */
  lst->size = 0;
  lst->items = NULL;
  return lst;
}


int epoll_ctl(uv__os390_epoll* lst,
              int op,
              int fd,
              struct epoll_event *event) {
  if(op == EPOLL_CTL_DEL) {
    if (fd >= lst->size || lst->items[fd].fd == -1) {
      errno = ENOENT;
      return -1;
    }
    lst->items[fd].fd = -1;
  } else if(op == EPOLL_CTL_ADD) {
    maybe_resize(lst, fd + 1);
    if (lst->items[fd].fd != -1) {
      errno = EEXIST;
      return -1;
    }
    lst->items[fd].fd = fd;
    lst->items[fd].events = event->events;
  } else if(op == EPOLL_CTL_MOD) {
    if (fd >= lst->size || lst->items[fd].fd == -1) {
      errno = ENOENT;
      return -1;
    }
    lst->items[fd].events = event->events;
  } else
    abort();

  return 0;
}


int epoll_wait(uv__os390_epoll* lst, struct epoll_event* events,
               int maxevents, int timeout) {
  size_t size;
  struct pollfd* pfds;
  int pollret;
  int reventcount;

  uv_mutex_lock(&global_epoll_lock);
  uv_mutex_unlock(&global_epoll_lock);
  size = lst->size;
  pfds = lst->items;
  pollret = poll(pfds, size, timeout);
  if(pollret == -1)
    return pollret;

  reventcount = 0;
  for (int i = 0; i < lst->size && i < maxevents; ++i) {
    struct epoll_event ev;

    ev.events = 0;
    ev.fd = pfds[i].fd;
    if(!pfds[i].revents)
      continue;

    if(pfds[i].revents & POLLRDNORM)
      ev.events = ev.events | POLLIN;

    if(pfds[i].revents & POLLWRNORM)
      ev.events = ev.events | POLLOUT;

    if(pfds[i].revents & POLLHUP)
      ev.events = ev.events | POLLHUP;

    pfds[i].revents = 0;
    events[reventcount++] = ev;
  }

  return reventcount;
}


int epoll_file_close(int fd) {
  QUEUE* q;

  uv_once(&once, epoll_init);
  uv_mutex_lock(&global_epoll_lock);
  QUEUE_FOREACH(q, &global_epoll_queue) {
    uv__os390_epoll* lst;

    lst = QUEUE_DATA(q, uv__os390_epoll, member);
    if (fd < lst->size && lst->items != NULL && lst->items[fd].fd != -1)
      lst->items[fd].fd = -1;
  }

  uv_mutex_unlock(&global_epoll_lock);
  return 0;
}

void epoll_queue_close(uv__os390_epoll* lst) {
  uv_mutex_lock(&global_epoll_lock);
  QUEUE_REMOVE(&lst->member);
  uv_mutex_unlock(&global_epoll_lock);
  uv__free(lst->items);
  lst->items = NULL;
}


int nanosleep(const struct timespec* req, struct timespec* rem) {
  unsigned nano;
  unsigned seconds;
  unsigned events;
  unsigned secrem;
  unsigned nanorem;
  int rv;
  int rc;
  int rsn;

  nano = (int)req->tv_nsec;
  seconds = req->tv_sec;
  events = CW_CONDVAR;

#if defined(_LP64)
  BPX4CTW(&seconds, &nano, &events, &secrem, &nanorem, &rv, &rc, &rsn);
#else
  BPX1CTW(&seconds, &nano, &events, &secrem, &nanorem, &rv, &rc, &rsn);
#endif

  assert(rv == -1 && errno == EAGAIN);

  if(rem != NULL) {
    rem->tv_nsec = nanorem;
    rem->tv_sec = secrem;
  }

  return 0;
}


char* mkdtemp(char* path) {
  static const char* tempchars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  static const size_t num_chars = 62;
  static const size_t num_x = 6;
  char *ep, *cp;
  unsigned int tries, i;
  size_t len;
  uint64_t v;
  int fd;
  int retval;
  int saved_errno;

  len = strlen(path);
  ep = path + len;
  if (len < num_x || strncmp(ep - num_x, "XXXXXX", num_x)) {
    errno = EINVAL;
    return NULL;
  }

  fd = open("/dev/urandom", O_RDONLY);
  if (fd == -1)
    return NULL;

  tries = TMP_MAX;
  retval = -1;
  do {
    if (read(fd, &v, sizeof(v)) != sizeof(v))
      break;

    cp = ep - num_x;
    for (i = 0; i < num_x; i++) {
      *cp++ = tempchars[v % num_chars];
      v /= num_chars;
    }

    if (mkdir(path, S_IRWXU) == 0) {
      retval = 0;
      break;
    }
    else if (errno != EEXIST)
      break;
  } while (--tries);

  saved_errno = errno;
  uv__close(fd);
  if (tries == 0) {
    errno = EEXIST;
    return NULL;
  }

  if (retval == -1) {
    errno = saved_errno;
    return NULL;
  }

  return path;
}


static int uv__getiovmaxlen(uv_stream_t* stream) {
  int bufsize;
  socklen_t optlen;

  if (stream->flags & UV_STREAM_BLOCKING)
    return INT_MAX;

  switch (stream->type) {
    case UV_TCP:
      optlen = sizeof (bufsize);
      if (getsockopt(uv__stream_fd(stream), SOL_SOCKET,
                     SO_SNDBUF, &bufsize, &optlen))
        return -1;
      return bufsize - 1;

    case UV_NAMED_PIPE:
      return _POSIX_PIPE_BUF - 1;

    default:
      return INT_MAX;
  }

  UNREACHABLE();
}


int uv__os390_write(uv_stream_t* stream, void *iov, ssize_t iovcnt) {
  int iovmaxlen;

  iovmaxlen = uv__getiovmaxlen(stream);
  if (iovmaxlen == -1)
    return -1;
  return write(uv__stream_fd(stream), iov,
               iovcnt > iovmaxlen ? iovmaxlen : iovcnt);
}


int uv__os390_writev(uv_stream_t* stream, struct iovec *iov,
                     int iovcnt) {
  /* This is merely a wrapper around writev to limit the
   * buffer size to the socket buffer size. Otherwise,
   * poll won't trigger a POLLOUT for the next write on
   * this socket.
   */
  struct iovec original_iovec;
  int original_iovcnt;
  int avail_buffer;
  int index;
  int n;

  /* TODO: instead of calculating iovmaxlen for every write,
   * store it in the uv_stream_t structure.
   */
  avail_buffer = uv__getiovmaxlen(stream);
  if (avail_buffer == -1)
    return -1;

  /* Find out if the write buffer size exceeds the socket
   * send buffer size
   */
  original_iovcnt = iovcnt;
  for (index = 0; index < iovcnt; ++index) {
    if (avail_buffer < iov[index].iov_len)
      break;
    avail_buffer -= iov[index].iov_len;
  }

  /* If yes, then copy the origin iovec to temporary storage
   * and modify the iovec to limit the buffer size
   */
  if (index < original_iovcnt) {
    original_iovec = iov[index];
    iov[index].iov_len = avail_buffer;
    iovcnt = index + 1;
  }

  n = writev(uv__stream_fd(stream), iov, iovcnt);
  if (index < original_iovcnt) {
    iov[index] = original_iovec;
    iovcnt = original_iovcnt;
  }

  return n;
}
