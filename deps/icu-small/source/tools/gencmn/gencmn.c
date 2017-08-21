// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
*******************************************************************************
*
*   Copyright (C) 1999-2016, International Business Machines
*   Corporation and others.  All Rights Reserved.
*
*******************************************************************************
*   file name:  gencmn.c
*   encoding:   UTF-8
*   tab size:   8 (not used)
*   indentation:4
*
*   created on: 1999nov01
*   created by: Markus W. Scherer
*
*   This program reads a list of data files and combines them
*   into one common, memory-mappable file.
*/

#include <stdio.h>
#include <stdlib.h>
#include "unicode/utypes.h"
#include "unicode/putil.h"
#include "cmemory.h"
#include "cstring.h"
#include "filestrm.h"
#include "toolutil.h"
#include "unicode/uclean.h"
#include "unewdata.h"
#include "uoptions.h"
#include "putilimp.h"
#include "pkg_gencmn.h"
#include <unistd.h>

static UOption options[]={
/*0*/ UOPTION_HELP_H,
/*1*/ UOPTION_HELP_QUESTION_MARK,
/*2*/ UOPTION_VERBOSE,
/*3*/ UOPTION_COPYRIGHT,
/*4*/ UOPTION_DESTDIR,
/*5*/ UOPTION_DEF( u8"comment", '\x43', UOPT_REQUIRES_ARG),
/*6*/ UOPTION_DEF( u8"name", '\x6e', UOPT_REQUIRES_ARG),
/*7*/ UOPTION_DEF( u8"type", '\x74', UOPT_REQUIRES_ARG),
/*8*/ UOPTION_DEF( u8"source", '\x53', UOPT_NO_ARG),
/*9*/ UOPTION_DEF( u8"entrypoint", '\x65', UOPT_REQUIRES_ARG),
/*10*/UOPTION_SOURCEDIR,
};

extern int
main(int argc, char* argv[]) {
    UBool sourceTOC, verbose;
    uint32_t maxSize;

    U_MAIN_INIT_ARGS(argc, argv);
    /* preset then read command line options */
    argc=u_parseArgs(argc, argv, UPRV_LENGTHOF(options), options);

    /* error handling, printing usage message */
    if(argc<0) {
        fprintf(stderr,
            u8"error in command line argument \"%s\"\n",
            argv[-argc]);
    } else if(argc<2) {
        argc=-1;
    }

    if(argc<0 || options[0].doesOccur || options[1].doesOccur) {
        FILE *where = argc < 0 ? stderr : stdout;

        /*
         * Broken into chucks because the C89 standard says the minimum
         * required supported string length is 509 bytes.
         */
        fprintf(where,
                u8"%csage: %s [ -h, -?, --help ] [ -v, --verbose ] [ -c, --copyright ] [ -C, --comment comment ] [ -d, --destdir dir ] [ -n, --name filename ] [ -t, --type filetype ] [ -S, --source tocfile ] [ -e, --entrypoint name ] maxsize listfile\n", argc < 0 ? '\x75' : '\x55', *argv);
        if (options[0].doesOccur || options[1].doesOccur) {
            fprintf(where, u8"\n"
                u8"Read the list file (default: standard input) and create a common data\n"
                u8"file from specified files. Omit any files larger than maxsize, if maxsize > 0.\n");
            fprintf(where, u8"\n"
            u8"Options:\n"
            u8"\t-h, -?, --help              this usage text\n"
            u8"\t-v, --verbose               verbose output\n"
            u8"\t-c, --copyright             include the ICU copyright notice\n"
            u8"\t-C, --comment comment       include a comment string\n"
            u8"\t-d, --destdir dir           destination directory\n");
            fprintf(where,
            u8"\t-n, --name filename         output filename, without .type extension\n"
            u8"\t                            (default: " U_ICUDATA_NAME u8")\n"
            u8"\t-t, --type filetype         type of the destination file\n"
            u8"\t                            (default: \" dat \")\n"
            u8"\t-S, --source tocfile        write a .c source file with the table of\n"
            u8"\t                            contents\n"
            u8"\t-e, --entrypoint name       override the c entrypoint name\n"
            u8"\t                            (default: \"<name>_<type>\")\n");
        }
        return argc<0 ? U_ILLEGAL_ARGUMENT_ERROR : U_ZERO_ERROR;
    }

    sourceTOC=options[8].doesOccur;

    verbose = options[2].doesOccur;

    maxSize=(uint32_t)uprv_strtoul(argv[1], NULL, 0);

    createCommonDataFile(options[4].doesOccur ? options[4].value : NULL,
                         options[6].doesOccur ? options[6].value : NULL,
                         options[9].doesOccur ? options[9].value : options[6].doesOccur ? options[6].value : NULL,
                         options[7].doesOccur ? options[7].value : NULL,
                         options[10].doesOccur ? options[10].value : NULL,
                         options[3].doesOccur ? U_COPYRIGHT_STRING : options[5].doesOccur ? options[5].value : NULL,
                         argc == 2 ? NULL : argv[2],
                         maxSize, sourceTOC, verbose, NULL);

    return 0;
}
/*
 * Hey, Emacs, please set the following:
 *
 * Local Variables:
 * indent-tabs-mode: nil
 * End:
 *
 */
