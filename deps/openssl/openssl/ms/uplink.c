#if (defined(_WIN64) || defined(_WIN32_WCE)) && !defined(UNICODE)
# define UNICODE
#endif
#if defined(UNICODE) && !defined(_UNICODE)
# define _UNICODE
#endif
#if defined(_UNICODE) && !defined(UNICODE)
# define UNICODE
#endif

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "uplink.h"
void OPENSSL_showfatal(const char *, ...);

static TCHAR msg[128];

static void unimplemented(void)
{
    OPENSSL_showfatal(sizeof(TCHAR) == sizeof(char) ? "\x25\x73\xa" : "\x25\x53\xa", msg);
    ExitProcess(1);
}

void OPENSSL_Uplink(volatile void **table, int index)
{
    static HMODULE volatile apphandle = NULL;
    static void **volatile applinktable = NULL;
    int len;
    void (*func) (void) = unimplemented;
    HANDLE h;
    void **p;

    /*
     * Note that the below code is not MT-safe in respect to msg buffer, but
     * what's the worst thing that can happen? Error message might be
     * misleading or corrupted. As error condition is fatal and should never
     * be risen, I accept the risk...
     */
    /*
     * One can argue that I should have used InterlockedExchangePointer or
     * something to update static variables and table[]. Well, store
     * instructions are as atomic as they can get and assigned values are
     * effectively constant... So that volatile qualifier should be
     * sufficient [it prohibits compiler to reorder memory access
     * instructions].
     */
    do {
        len = _sntprintf(msg, sizeof(msg) / sizeof(TCHAR),
                         _T("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x55\x70\x6c\x69\x6e\x6b\x28\x25\x70\x2c\x25\x30\x32\x58\x29\x3a\x20"), table, index);
        _tcscpy(msg + len, _T("\x75\x6e\x69\x6d\x70\x6c\x65\x6d\x65\x6e\x74\x65\x64\x20\x66\x75\x6e\x63\x74\x69\x6f\x6e"));

        if ((h = apphandle) == NULL) {
            if ((h = GetModuleHandle(NULL)) == NULL) {
                apphandle = (HMODULE) - 1;
                _tcscpy(msg + len, _T("\x6e\x6f\x20\x68\x6f\x73\x74\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e"));
                break;
            }
            apphandle = h;
        }
        if ((h = apphandle) == (HMODULE) - 1) /* revalidate */
            break;

        if (applinktable == NULL) {
            void **(*applink) ();

            applink = (void **(*)())GetProcAddress(h, "\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x41\x70\x70\x6c\x69\x6e\x6b");
            if (applink == NULL) {
                apphandle = (HMODULE) - 1;
                _tcscpy(msg + len, _T("\x6e\x6f\x20\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x41\x70\x70\x6c\x69\x6e\x6b"));
                break;
            }
            p = (*applink) ();
            if (p == NULL) {
                apphandle = (HMODULE) - 1;
                _tcscpy(msg + len, _T("\x6e\x6f\x20\x41\x70\x70\x6c\x69\x6e\x6b\x54\x61\x62\x6c\x65"));
                break;
            }
            applinktable = p;
        } else
            p = applinktable;

        if (index > (int)p[0])
            break;

        if (p[index])
            func = p[index];
    } while (0);

    table[index] = func;
}

#if defined(_MSC_VER) && defined(_M_IX86) && !defined(OPENSSL_NO_INLINE_ASM)
# define LAZY(i)         \
__declspec(naked) static void lazy##i (void) {  \
        _asm    push i                          \
        _asm    push OFFSET OPENSSL_UplinkTable \
        _asm    call OPENSSL_Uplink             \
        _asm    add  esp,8                      \
        _asm    jmp  OPENSSL_UplinkTable+4*i    }

# if APPLINK_MAX>25
#  error "\x41\x64\x64\x20\x6d\x6f\x72\x65\x20\x73\x74\x75\x62\x73\x2e\x2e\x2e"
# endif
/* make some in advance... */
LAZY(1) LAZY(2) LAZY(3) LAZY(4) LAZY(5)
    LAZY(6) LAZY(7) LAZY(8) LAZY(9) LAZY(10)
    LAZY(11) LAZY(12) LAZY(13) LAZY(14) LAZY(15)
    LAZY(16) LAZY(17) LAZY(18) LAZY(19) LAZY(20)
    LAZY(21) LAZY(22) LAZY(23) LAZY(24) LAZY(25)
void *OPENSSL_UplinkTable[] = {
    (void *)APPLINK_MAX,
    lazy1, lazy2, lazy3, lazy4, lazy5,
    lazy6, lazy7, lazy8, lazy9, lazy10,
    lazy11, lazy12, lazy13, lazy14, lazy15,
    lazy16, lazy17, lazy18, lazy19, lazy20,
    lazy21, lazy22, lazy23, lazy24, lazy25,
};
#endif

#ifdef SELFTEST
main()
{
    UP_fprintf(UP_stdout, "\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21\xa");
}
#endif
