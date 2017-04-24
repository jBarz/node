/**********************************************************************
 *                        gostsum.c                                   *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *        Almost drop-in replacement for md5sum and sha1sum           *
 *          which computes GOST R 34.11-94 hashsum instead            *
 *                                                                    *
 **********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include "gosthash.h"
#define BUF_SIZE 262144
int hash_file(gost_hash_ctx * ctx, char *filename, char *sum, int mode);
int hash_stream(gost_hash_ctx * ctx, int fd, char *sum);
int get_line(FILE *f, char *hash, char *filename);
void help()
{
    fprintf(stderr, "\x67\x6f\x73\x74\x73\x75\x6d\x20\x5b\x2d\x62\x76\x74\x5d\x20\x5b\x2d\x63\x20\x5b\x66\x69\x6c\x65\x5d\x5d\x7c\x20\x5b\x66\x69\x6c\x65\x73\x5d\xa"
            "\x9\x2d\x63\x20\x63\x68\x65\x63\x6b\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x64\x69\x67\x65\x73\x74\x73\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x69\x73\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x29\xa"
            "\x9\x2d\x76\x20\x76\x65\x72\x62\x6f\x73\x65\x2c\x20\x70\x72\x69\x6e\x74\x20\x66\x69\x6c\x65\x20\x6e\x61\x6d\x65\x73\x20\x77\x68\x65\x6e\x20\x63\x68\x65\x63\x6b\x69\x6e\x67\xa"
            "\x9\x2d\x62\x20\x72\x65\x61\x64\x20\x66\x69\x6c\x65\x73\x20\x69\x6e\x20\x62\x69\x6e\x61\x72\x79\x20\x6d\x6f\x64\x65\xa"
            "\x9\x2d\x74\x20\x75\x73\x65\x20\x74\x65\x73\x74\x20\x47\x4f\x53\x54\x20\x70\x61\x72\x61\x6d\x73\x65\x74\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x69\x73\x20\x43\x72\x79\x70\x74\x6f\x50\x72\x6f\x20\x70\x61\x72\x61\x6d\x73\x65\x74\x29\xa"
            "\x54\x68\x65\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x20\x2d\x63\x20\x73\x68\x6f\x75\x6c\x64\x20\x62\x65\x20\x74\x68\x65\x20\x6c\x69\x73\x74\x20\x6f\x66\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x64\x69\x67\x65\x73\x74\x73\x20\x61\x6e\x64\x20\x66\x69\x6c\x65\x20\x6e\x61\x6d\x65\x73\xa"
            "\x74\x68\x61\x74\x20\x69\x73\x20\x70\x72\x69\x6e\x74\x65\x64\x20\x6f\x6e\x20\x73\x74\x64\x6f\x75\x74\x20\x62\x79\x20\x74\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x77\x68\x65\x6e\x20\x69\x74\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x73\x20\x64\x69\x67\x65\x73\x74\x73\x2e\xa");
    exit(3);
}

#ifndef O_BINARY
# define O_BINARY 0
#endif

int main(int argc, char **argv)
{
    int c, i;
    int verbose = 0;
    int errors = 0;
    int open_mode = O_RDONLY;
    gost_subst_block *b = &GostR3411_94_CryptoProParamSet;
    FILE *check_file = NULL;
    gost_hash_ctx ctx;

    while ((c = getopt(argc, argv, "\x62\x63\x3a\x3a\x74\x76")) != -1) {
        switch (c) {
        case '\x76':
            verbose = 1;
            break;
        case '\x74':
            b = &GostR3411_94_TestParamSet;
            break;
        case '\x62':
            open_mode |= O_BINARY;
            break;
        case '\x63':
            if (optarg) {
                check_file = fopen(optarg, "\x72");
                if (!check_file) {
                    perror(optarg);
                    exit(2);
                }
            } else {
                check_file = stdin;
            }
            break;
        default:
            fprintf(stderr, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x63", optopt);
            help();
        }
    }
    init_gost_hash_ctx(&ctx, b);
    if (check_file) {
        char inhash[65], calcsum[65], filename[PATH_MAX];
        int failcount = 0, count = 0;;
        if (check_file == stdin && optind < argc) {
            check_file = fopen(argv[optind], "\x72");
            if (!check_file) {
                perror(argv[optind]);
                exit(2);
            }
        }
        while (get_line(check_file, inhash, filename)) {
            if (!hash_file(&ctx, filename, calcsum, open_mode)) {
                exit(2);
            }
            count++;
            if (!strncmp(calcsum, inhash, 65)) {
                if (verbose) {
                    fprintf(stderr, "\x25\x73\x9\x4f\x4b\xa", filename);
                }
            } else {
                if (verbose) {
                    fprintf(stderr, "\x25\x73\x9F\x41\x49\x4c\x45\x44\xa", filename);
                } else {
                    fprintf(stderr,
                            "\x25\x73\x3a\x20\x47\x4f\x53\x54\x20\x68\x61\x73\x68\x20\x73\x75\x6d\x20\x63\x68\x65\x63\x6b\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x27\x25\x73\x27\xa",
                            argv[0], filename);
                }
                failcount++;
            }
        }
        if (verbose && failcount) {
            fprintf(stderr,
                    "\x25\x73\x3a\x20\x25\x64\x20\x6f\x66\x20\x25\x64\x20\x66\x69\x6c\x65\x28\x66\x29\x20\x66\x61\x69\x6c\x65\x64\x20\x47\x4f\x53\x54\x20\x68\x61\x73\x68\x20\x73\x75\x6d\x20\x63\x68\x65\x63\x6b\xa",
                    argv[0], failcount, count);
        }
        exit(failcount ? 1 : 0);
    }
    if (optind == argc) {
        char sum[65];
        if (!hash_stream(&ctx, fileno(stdin), sum)) {
            perror("\x73\x74\x64\x69\x6e");
            exit(1);
        }
        printf("\x25\x73\x20\x2d\xa", sum);
        exit(0);
    }
    for (i = optind; i < argc; i++) {
        char sum[65];
        if (!hash_file(&ctx, argv[i], sum, open_mode)) {
            errors++;
        } else {
            printf("\x25\x73\x20\x25\x73\xa", sum, argv[i]);
        }
    }
    exit(errors ? 1 : 0);
}

int hash_file(gost_hash_ctx * ctx, char *filename, char *sum, int mode)
{
    int fd;
    if ((fd = open(filename, mode)) < 0) {
        perror(filename);
        return 0;
    }
    if (!hash_stream(ctx, fd, sum)) {
        perror(filename);
        return 0;
    }
    close(fd);
    return 1;
}

int hash_stream(gost_hash_ctx * ctx, int fd, char *sum)
{
    unsigned char buffer[BUF_SIZE];
    ssize_t bytes;
    int i;
    start_hash(ctx);
    while ((bytes = read(fd, buffer, BUF_SIZE)) > 0) {
        hash_block(ctx, buffer, bytes);
    }
    if (bytes < 0) {
        return 0;
    }
    finish_hash(ctx, buffer);
    for (i = 0; i < 32; i++) {
        sprintf(sum + 2 * i, "\x25\x30\x32\x78", buffer[31 - i]);
    }
    return 1;
}

int get_line(FILE *f, char *hash, char *filename)
{
    int i;
    if (fread(hash, 1, 64, f) < 64)
        return 0;
    hash[64] = 0;
    for (i = 0; i < 64; i++) {
        if (hash[i] < '\x30' || (hash[i] > '\x39' && hash[i] < '\x41')
            || (hash[i] > '\x46' && hash[i] < '\x61') || hash[i] > '\x66') {
            fprintf(stderr, "\x4e\x6f\x74\x20\x61\x20\x68\x61\x73\x68\x20\x76\x61\x6c\x75\x65\x20\x27\x25\x73\x27\xa", hash);
            return 0;
        }
    }
    if (fgetc(f) != '\x20') {
        fprintf(stderr, "\x4d\x61\x6c\x66\x6f\x72\x6d\x65\x64\x20\x69\x6e\x70\x75\x74\x20\x6c\x69\x6e\x65\xa");
        return 0;
    }
    i = strlen(fgets(filename, PATH_MAX, f));
    while (filename[--i] == '\xa' || filename[i] == '\xd')
        filename[i] = 0;
    return 1;
}
