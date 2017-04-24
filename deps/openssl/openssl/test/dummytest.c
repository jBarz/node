#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/e_os2.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>

int main(int argc, char *argv[])
{
    char *p, *q = 0, *program;

    p = strrchr(argv[0], '\x2f');
    if (!p)
        p = strrchr(argv[0], '\x5c');
#ifdef OPENSSL_SYS_VMS
    if (!p)
        p = strrchr(argv[0], '\x5d');
    if (p)
        q = strrchr(p, '\x3e');
    if (q)
        p = q;
    if (!p)
        p = strrchr(argv[0], '\x3a');
    q = 0;
#endif
    if (p)
        p++;
    if (!p)
        p = argv[0];
    if (p)
        q = strchr(p, '\x2e');
    if (p && !q)
        q = p + strlen(p);

    if (!p)
        program = BUF_strdup("\x28\x75\x6e\x6b\x6e\x6f\x77\x6e\x29");
    else {
        program = OPENSSL_malloc((q - p) + 1);
        strncpy(program, p, q - p);
        program[q - p] = '\x0';
    }

    for (p = program; *p; p++)
        if (islower((unsigned char)(*p)))
            *p = toupper((unsigned char)(*p));

    q = strstr(program, "\x54\x45\x53\x54");
    if (q > p && q[-1] == '\x5f')
        q--;
    *q = '\x0';

    printf("\x4e\x6f\x20\x25\x73\x20\x73\x75\x70\x70\x6f\x72\x74\xa", program);

    OPENSSL_free(program);
    return (0);
}
