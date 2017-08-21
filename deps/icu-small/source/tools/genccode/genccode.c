// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
 *******************************************************************************
 *   Copyright (C) 1999-2016, International Business Machines
 *   Corporation and others.  All Rights Reserved.
 *******************************************************************************
 *   file name:  gennames.c
 *   encoding:   UTF-8
 *   tab size:   8 (not used)
 *   indentation:4
 *
 *   created on: 1999nov01
 *   created by: Markus W. Scherer
 *
 *   This program reads a binary file and creates a C source code file
 *   with a byte array that contains the data of the binary file.
 *
 *   12/09/1999  weiv    Added multiple file handling
 */
#define _AE_BIMODAL
#include "unicode/utypes.h"

#if U_PLATFORM_HAS_WIN32_API
#   define VC_EXTRALEAN
#   define WIN32_LEAN_AND_MEAN
#   define NOUSER
#   define NOSERVICE
#   define NOIME
#   define NOMCX
#include <windows.h>
#include <time.h>
#endif

#if U_PLATFORM_IS_LINUX_BASED && U_HAVE_ELF_H
#   define U_ELF
#endif

#ifdef U_ELF
#   include <elf.h>
#   if defined(ELFCLASS64)
#       define U_ELF64
#   endif
    /* Old elf.h headers may not have EM_X86_64, or have EM_X8664 instead. */
#   ifndef EM_X86_64
#       define EM_X86_64 62
#   endif
#   define ICU_ENTRY_OFFSET 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include "unicode/putil.h"
#include "cmemory.h"
#include "cstring.h"
#include "filestrm.h"
#include "toolutil.h"
#include "unicode/uclean.h"
#include "uoptions.h"
#include "pkg_genc.h"
#include <unistd.h>

enum {
  kOptHelpH = 0,
  kOptHelpQuestionMark,
  kOptDestDir,
  kOptName,
  kOptEntryPoint,
#ifdef CAN_GENERATE_OBJECTS
  kOptObject,
  kOptMatchArch,
#endif
  kOptFilename,
  kOptAssembly
};

static UOption options[]={
/*0*/UOPTION_HELP_H,
     UOPTION_HELP_QUESTION_MARK,
     UOPTION_DESTDIR,
     UOPTION_DEF(u8"name", '\x6e', UOPT_REQUIRES_ARG),
     UOPTION_DEF(u8"entrypoint", '\x65', UOPT_REQUIRES_ARG),
#ifdef CAN_GENERATE_OBJECTS
/*5*/UOPTION_DEF("object", 'o', UOPT_NO_ARG),
     UOPTION_DEF(u8"match-arch", '\x6d', UOPT_REQUIRES_ARG),
#endif
     UOPTION_DEF(u8"filename", '\x66', UOPT_REQUIRES_ARG),
     UOPTION_DEF(u8"assembly", '\x61', UOPT_REQUIRES_ARG)
};

#define CALL_WRITECCODE     '\x63'
#define CALL_WRITEASSEMBLY  '\x61'
#define CALL_WRITEOBJECT    '\x6f'
extern int
main(int argc, char* argv[]) {
   
    UBool verbose = TRUE;
    char writeCode;

    U_MAIN_INIT_ARGS(argc, argv);

    options[kOptDestDir].value = u8".";

    /* read command line options */
    argc=u_parseArgs(argc, argv, UPRV_LENGTHOF(options), options);

    /* error handling, printing usage message */
    if(argc<0) {
        __fprintf_a(stderr,
            u8"error in command line argument \"%s\"\n",
            argv[-argc]);
    }
    if(argc<0 || options[kOptHelpH].doesOccur || options[kOptHelpQuestionMark].doesOccur) {
        __fprintf_a(stderr,
            u8"usage: %s [-options] filename1 filename2 ...\n"
            u8"\tread each binary input file and \n"
            u8"\tcreate a .c file with a byte array that contains the input file's data\n"
            u8"options:\n"
            u8"\t-h or -? or --help  this usage text\n"
            u8"\t-d or --destdir     destination directory, followed by the path\n"
            u8"\t-n or --name        symbol prefix, followed by the prefix\n"
            u8"\t-e or --entrypoint  entry point name, followed by the name (_dat will be appended)\n"
            u8"\t-r or --revision    Specify a version\n"
            , argv[0]);
#ifdef CAN_GENERATE_OBJECTS
        __fprintf_a(stderr,
            u8"\t-o or --object      write a .obj file instead of .c\n"
            u8"\t-m or --match-arch file.o  match the architecture (CPU, 32/64 bits) of the specified .o\n"
            u8"\t                    ELF format defaults to i386. Windows defaults to the native platform.\n");
#endif
        __fprintf_a(stderr,
            u8"\t-f or --filename    Specify an alternate base filename. (default: symbolname_typ)\n"
            u8"\t-a or --assembly    Create assembly file. (possible values are: ");

        printAssemblyHeadersToStdErr();
    } else {
        const char *message, *filename;
        /* TODO: remove void (*writeCode)(const char *, const char *); */

        if(options[kOptAssembly].doesOccur) {
            message=u8"generating assembly code for %s\n";
            writeCode = CALL_WRITEASSEMBLY;
            /* TODO: remove writeCode=&writeAssemblyCode; */

            if (!checkAssemblyHeaderName(options[kOptAssembly].value)) {
                __fprintf_a(stderr,
                    u8"Assembly type \"%s\" is unknown.\n", options[kOptAssembly].value);
                return -1;
            }
        }
#ifdef CAN_GENERATE_OBJECTS
        else if(options[kOptObject].doesOccur) {
            message=u8"generating object code for %s\n";
            writeCode = CALL_WRITEOBJECT;
            /* TODO: remove writeCode=&writeObjectCode; */
        }
#endif
        else
        {
            message=u8"generating C code for %s\n";
            writeCode = CALL_WRITECCODE;
            /* TODO: remove writeCode=&writeCCode; */
        }
        while(--argc) {
            filename=getLongPathname(argv[argc]);
            if (verbose) {
                __fprintf_a(stdout, message, filename);
            }

            switch (writeCode) {
            case CALL_WRITECCODE:
                writeCCode(filename, options[kOptDestDir].value,
                           options[kOptName].doesOccur ? options[kOptName].value : NULL,
                           options[kOptFilename].doesOccur ? options[kOptFilename].value : NULL,
                           NULL);
                break;
            case CALL_WRITEASSEMBLY:
                writeAssemblyCode(filename, options[kOptDestDir].value,
                                  options[kOptEntryPoint].doesOccur ? options[kOptEntryPoint].value : NULL,
                                  options[kOptFilename].doesOccur ? options[kOptFilename].value : NULL,
                                  NULL);
                break;
#ifdef CAN_GENERATE_OBJECTS
            case CALL_WRITEOBJECT:
                writeObjectCode(filename, options[kOptDestDir].value,
                                options[kOptEntryPoint].doesOccur ? options[kOptEntryPoint].value : NULL,
                                options[kOptMatchArch].doesOccur ? options[kOptMatchArch].value : NULL,
                                options[kOptFilename].doesOccur ? options[kOptFilename].value : NULL,
                                NULL);
                break;
#endif
            default:
                /* Should never occur. */
                break;
            }
            /* TODO: remove writeCode(filename, options[kOptDestDir].value); */
        }
    }

    return 0;
}
