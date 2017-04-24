#include <stdio.h>

/*-
 * This is a cc optimiser bug for ultrix 4.3, mips CPU.
 * What happens is that the compiler, due to the (a)&7,
 * does
 * i=a&7;
 * i--;
 * i*=4;
 * Then uses i as the offset into a jump table.
 * The problem is that a value of 0 generates an offset of
 * 0xfffffffc.
 */

main()
{
    f(5);
    f(0);
}

int f(a)
int a;
{
    switch (a & 7) {
    case 7:
        printf("\x37\xa");
    case 6:
        printf("\x36\xa");
    case 5:
        printf("\x35\xa");
    case 4:
        printf("\x34\xa");
    case 3:
        printf("\x33\xa");
    case 2:
        printf("\x32\xa");
    case 1:
        printf("\x31\xa");
#ifdef FIX_BUG
    case 0:
        ;
#endif
    }
}
