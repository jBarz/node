#if defined( __VMS) && !defined( OPENSSL_NO_DECC_INIT) && \
 defined( __DECC) && !defined( __VAX) && (__CRTL_VER >= 70301000)
# define USE_DECC_INIT 1
#endif

#ifdef USE_DECC_INIT

/*-
 * 2010-04-26 SMS.
 *
 *----------------------------------------------------------------------
 *
 *       decc_init()
 *
 *    On non-VAX systems, uses LIB$INITIALIZE to set a collection of C
 *    RTL features without using the DECC$* logical name method.
 *
 *----------------------------------------------------------------------
 */

# include <stdio.h>
# include <stdlib.h>
# include <unixlib.h>

/* Global storage. */

/* Flag to sense if decc_init() was called. */

int decc_init_done = -1;

/* Structure to hold a DECC$* feature name and its desired value. */

typedef struct {
    char *name;
    int value;
} decc_feat_t;

/*
 * Array of DECC$* feature names and their desired values. Note:
 * DECC$ARGV_PARSE_STYLE is the urgent one.
 */

decc_feat_t decc_feat_array[] = {
    /* Preserve command-line case with SET PROCESS/PARSE_STYLE=EXTENDED */
    {"\x44\x45\x43\x43\x24\x41\x52\x47\x56\x5f\x50\x41\x52\x53\x45\x5f\x53\x54\x59\x4c\x45", 1},

    /* Preserve case for file names on ODS5 disks. */
    {"\x44\x45\x43\x43\x24\x45\x46\x53\x5f\x43\x41\x53\x45\x5f\x50\x52\x45\x53\x45\x52\x56\x45", 1},

    /*
     * Enable multiple dots (and most characters) in ODS5 file names, while
     * preserving VMS-ness of ";version".
     */
    {"\x44\x45\x43\x43\x24\x45\x46\x53\x5f\x43\x48\x41\x52\x53\x45\x54", 1},

    /* List terminator. */
    {(char *)NULL, 0}
};

/* LIB$INITIALIZE initialization function. */

static void decc_init(void)
{
    char *openssl_debug_decc_init;
    int verbose = 0;
    int feat_index;
    int feat_value;
    int feat_value_max;
    int feat_value_min;
    int i;
    int sts;

    /* Get debug option. */
    openssl_debug_decc_init = getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x44\x45\x42\x55\x47\x5f\x44\x45\x43\x43\x5f\x49\x4e\x49\x54");
    if (openssl_debug_decc_init != NULL) {
        verbose = strtol(openssl_debug_decc_init, NULL, 10);
        if (verbose <= 0) {
            verbose = 1;
        }
    }

    /* Set the global flag to indicate that LIB$INITIALIZE worked. */
    decc_init_done = 1;

    /* Loop through all items in the decc_feat_array[]. */

    for (i = 0; decc_feat_array[i].name != NULL; i++) {
        /* Get the feature index. */
        feat_index = decc$feature_get_index(decc_feat_array[i].name);
        if (feat_index >= 0) {
            /* Valid item.  Collect its properties. */
            feat_value = decc$feature_get_value(feat_index, 1);
            feat_value_min = decc$feature_get_value(feat_index, 2);
            feat_value_max = decc$feature_get_value(feat_index, 3);

            /* Check the validity of our desired value. */
            if ((decc_feat_array[i].value >= feat_value_min) &&
                (decc_feat_array[i].value <= feat_value_max)) {
                /* Valid value.  Set it if necessary. */
                if (feat_value != decc_feat_array[i].value) {
                    sts = decc$feature_set_value(feat_index,
                                                 1, decc_feat_array[i].value);

                    if (verbose > 1) {
                        fprintf(stderr, "\x20\x25\x73\x20\x3d\x20\x25\x64\x2c\x20\x73\x74\x73\x20\x3d\x20\x25\x64\x2e\xa",
                                decc_feat_array[i].name,
                                decc_feat_array[i].value, sts);
                    }
                }
            } else {
                /* Invalid DECC feature value. */
                fprintf(stderr,
                        "\x20\x49\x4e\x56\x41\x4c\x49\x44\x20\x44\x45\x43\x43\x24\x46\x45\x41\x54\x55\x52\x45\x20\x56\x41\x4c\x55\x45\x2c\x20\x25\x64\x3a\x20\x25\x64\x20\x3c\x3d\x20\x25\x73\x20\x3c\x3d\x20\x25\x64\x2e\xa",
                        feat_value,
                        feat_value_min, decc_feat_array[i].name,
                        feat_value_max);
            }
        } else {
            /* Invalid DECC feature name. */
            fprintf(stderr,
                    "\x20\x55\x4e\x4b\x4e\x4f\x57\x4e\x20\x44\x45\x43\x43\x24\x46\x45\x41\x54\x55\x52\x45\x3a\x20\x25\x73\x2e\xa", decc_feat_array[i].name);
        }
    }

    if (verbose > 0) {
        fprintf(stderr, "\x20\x44\x45\x43\x43\x5f\x49\x4e\x49\x54\x20\x63\x6f\x6d\x70\x6c\x65\x74\x65\x2e\xa");
    }
}

/* Get "decc_init()" into a valid, loaded LIB$INITIALIZE PSECT. */

# pragma nostandard

/*
 * Establish the LIB$INITIALIZE PSECTs, with proper alignment and other
 * attributes.  Note that "nopic" is significant only on VAX.
 */
# pragma extern_model save

# if __INITIAL_POINTER_SIZE == 64
#  define PSECT_ALIGN 3
# else
#  define PSECT_ALIGN 2
# endif

# pragma extern_model strict_refdef "LIB$INITIALIZ" PSECT_ALIGN, nopic, nowrt
const int spare[8] = { 0 };

# pragma extern_model strict_refdef "LIB$INITIALIZE" PSECT_ALIGN, nopic, nowrt
void (*const x_decc_init) () = decc_init;

# pragma extern_model restore

/* Fake reference to ensure loading the LIB$INITIALIZE PSECT. */

# pragma extern_model save

int LIB$INITIALIZE(void);

# pragma extern_model strict_refdef
int dmy_lib$initialize = (int)LIB$INITIALIZE;

# pragma extern_model restore

# pragma standard

#else                           /* def USE_DECC_INIT */

/* Dummy code to avoid a %CC-W-EMPTYFILE complaint. */
int decc_init_dummy(void);

#endif                          /* def USE_DECC_INIT */
