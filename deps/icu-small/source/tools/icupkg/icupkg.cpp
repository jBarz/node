// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
*******************************************************************************
*
*   Copyright (C) 2005-2014, International Business Machines
*   Corporation and others.  All Rights Reserved.
*
*******************************************************************************
*   file name:  icupkg.cpp
*   encoding:   UTF-8
*   tab size:   8 (not used)
*   indentation:4
*
*   created on: 2005jul29
*   created by: Markus W. Scherer
*
*   This tool operates on ICU data (.dat package) files.
*   It takes one as input, or creates an empty one, and can remove, add, and
*   extract data pieces according to command-line options.
*   At the same time, it swaps each piece to a consistent set of platform
*   properties as desired.
*   Useful as an install-time tool for shipping only one flavor of ICU data
*   and preparing data files for the target platform.
*   Also for customizing ICU data (pruning, augmenting, replacing) and for
*   taking it apart.
*   Subsumes functionality and implementation code from
*   gencmn, decmn, and icuswap tools.
*   Will not work with data DLLs (shared libraries).
*/
#define _AE_BIMODAL
#include "unicode/utypes.h"
#include "unicode/putil.h"
#include "cstring.h"
#include "toolutil.h"
#include "uoptions.h"
#include "uparse.h"
#include "filestrm.h"
#include "package.h"
#include "pkg_icu.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

U_NAMESPACE_USE

// TODO: add --matchmode=regex for using the ICU regex engine for item name pattern matching?

// general definitions ----------------------------------------------------- ***

// main() ------------------------------------------------------------------ ***

static void
printUsage(const char *pname, UBool isHelp) {
    FILE *where=isHelp ? stdout : stderr;

    __fprintf_a(where,
            u8"%csage: %s [-h|-?|--help ] [-tl|-tb|-te] [-c] [-C comment]\n"
            u8"\t[-a list] [-r list] [-x list] [-l [-o outputListFileName]]\n"
            u8"\t[-s path] [-d path] [-w] [-m mode]\n"
            u8"\t[--auto_toc_prefix] [--auto_toc_prefix_with_type] [--toc_prefix]\n"
            u8"\tinfilename [outfilename]\n",
            isHelp ? '\x55' : '\x75', pname);
    if(isHelp) {
        __fprintf_a(where,
            u8"\n"
            u8"Read the input ICU .dat package file, modify it according to the options,\n"
            u8"swap it to the desired platform properties (charset & endianness),\n"
            u8"and optionally write the resulting ICU .dat package to the output file.\n"
            u8"Items are removed, then added, then extracted and listed.\n"
            u8"An ICU .dat package is written if items are removed or added,\n"
            u8"or if the input and output filenames differ,\n"
            u8"or if the --writepkg (-w) option is set.\n");
        __fprintf_a(where,
            u8"\n"
            u8"If the input filename is \"new\" then an empty package is created.\n"
            u8"If the output filename is missing, then it is automatically generated\n"
            u8"from the input filename: If the input filename ends with an l, b, or e\n"
            u8"matching its platform properties, then the output filename will\n"
            u8"contain the letter from the -t (--type) option.\n");
        __fprintf_a(where,
            u8"\n"
            u8"This tool can also be used to just swap a single ICU data file, replacing the\n"
            u8"former icuswap tool. For this mode, provide the infilename (and optional\n"
            u8"outfilename) for a non-package ICU data file.\n"
            u8"Allowed options include -t, -w, -s and -d.\n"
            u8"The filenames can be absolute, or relative to the source/dest dir paths.\n"
            u8"Other options are not allowed in this mode.\n");
        __fprintf_a(where,
            u8"\n"
            u8"Options:\n"
            u8"\t(Only the last occurrence of an option is used.)\n"
            u8"\n"
            u8"\t-h or -? or --help    print this message and exit\n");
        __fprintf_a(where,
            u8"\n"
            u8"\t-tl or --type l   output for little-endian/ASCII charset family\n"
            u8"\t-tb or --type b   output for big-endian/ASCII charset family\n"
            u8"\t-te or --type e   output for big-endian/EBCDIC charset family\n"
            u8"\t                  The output type defaults to the input type.\n"
            u8"\n"
            u8"\t-c or --copyright include the ICU copyright notice\n"
            u8"\t-C comment or --comment comment   include a comment string\n");
        __fprintf_a(where,
            u8"\n"
            u8"\t-a list or --add list      add items to the package\n"
            u8"\t-r list or --remove list   remove items from the package\n"
            u8"\t-x list or --extract list  extract items from the package\n"
            u8"\tThe list can be a single item's filename,\n"
            u8"\tor a .txt filename with a list of item filenames,\n"
            u8"\tor an ICU .dat package filename.\n");
        __fprintf_a(where,
            u8"\n"
            u8"\t-w or --writepkg  write the output package even if no items are removed\n"
            u8"\t                  or added (e.g., for only swapping the data)\n");
        __fprintf_a(where,
            u8"\n"
            u8"\t-m mode or --matchmode mode  set the matching mode for item names with\n"
            u8"\t                             wildcards\n"
            u8"\t        noslash: the '*' wildcard does not match the '/' tree separator\n");
        __fprintf_a(where,
            u8"\n"
            u8"\tIn the .dat package, the Table of Contents (ToC) contains an entry\n"
            u8"\tfor each item of the form prefix/tree/itemname .\n"
            u8"\tThe prefix normally matches the package basename, and icupkg checks that,\n"
            u8"\tbut this is not necessary when ICU need not find and load the package by filename.\n"
            u8"\tICU package names end with the platform type letter, and thus differ\n"
            u8"\tbetween platform types. This is not required for user data packages.\n");
        __fprintf_a(where,
            u8"\n"
            u8"\t--auto_toc_prefix            automatic ToC entries prefix\n"
            u8"\t                             Uses the prefix of the first entry of the\n"
            u8"\t                             input package, rather than its basename.\n"
            u8"\t                             Requires a non-empty input package.\n"
            u8"\t--auto_toc_prefix_with_type  auto_toc_prefix + adjust platform type\n"
            u8"\t                             Same as auto_toc_prefix but also checks that\n"
            u8"\t                             the prefix ends with the input platform\n"
            u8"\t                             type letter, and modifies it to the output\n"
            u8"\t                             platform type letter.\n"
            u8"\t                At most one of the auto_toc_prefix options\n"
            u8"\t                can be used at a time.\n"
            u8"\t--toc_prefix prefix          ToC prefix to be used in the output package\n"
            u8"\t                             Overrides the package basename\n"
            u8"\t                             and --auto_toc_prefix.\n"
            u8"\t                             Cannot be combined with --auto_toc_prefix_with_type.\n");
        /*
         * Usage text columns, starting after the initial TAB.
         *      1         2         3         4         5         6         7         8
         *     901234567890123456789012345678901234567890123456789012345678901234567890
         */
        __fprintf_a(where,
            u8"\n"
            u8"\tList file syntax: Items are listed on one or more lines and separated\n"
            u8"\tby whitespace (space+tab).\n"
            u8"\tComments begin with # and are ignored. Empty lines are ignored.\n"
            u8"\tLines where the first non-whitespace character is one of %s\n"
            u8"\tare also ignored, to reserve for future syntax.\n",
            U_PKG_RESERVED_CHARS);
        __fprintf_a(where,
            u8"\tItems for removal or extraction may contain a single '*' wildcard\n"
            u8"\tcharacter. The '*' matches zero or more characters.\n"
            u8"\tIf --matchmode noslash (-m noslash) is set, then the '*'\n"
            u8"\tdoes not match '/'.\n");
        __fprintf_a(where,
            u8"\n"
            u8"\tItems must be listed relative to the package, and the --sourcedir or\n"
            u8"\tthe --destdir path will be prepended.\n"
            u8"\tThe paths are only prepended to item filenames while adding or\n"
            u8"\textracting items, not to ICU .dat package or list filenames.\n"
            u8"\t\n"
            u8"\tPaths may contain '/' instead of the platform's\n"
            u8"\tfile separator character, and are converted as appropriate.\n");
        __fprintf_a(where,
            u8"\n"
            u8"\t-s path or --sourcedir path  directory for the --add items\n"
            u8"\t-d path or --destdir path    directory for the --extract items\n"
            u8"\n"
            u8"\t-l or --list                 list the package items\n"
            u8"\t                             (after modifying the package)\n"
            u8"\t                             to stdout or to output list file\n"
            u8"\t-o path or --outlist path    path/filename for the --list output\n");
    }
}

static UOption options[]={
    UOPTION_HELP_H,
    UOPTION_HELP_QUESTION_MARK,
    UOPTION_DEF(u8"type", '\x74', UOPT_REQUIRES_ARG),

    UOPTION_COPYRIGHT,
    UOPTION_DEF(u8"comment", '\x43', UOPT_REQUIRES_ARG),

    UOPTION_SOURCEDIR,
    UOPTION_DESTDIR,

    UOPTION_DEF(u8"writepkg", '\x77', UOPT_NO_ARG),

    UOPTION_DEF(u8"matchmode", '\x6d', UOPT_REQUIRES_ARG),

    UOPTION_DEF(u8"add", '\x61', UOPT_REQUIRES_ARG),
    UOPTION_DEF(u8"remove", '\x72', UOPT_REQUIRES_ARG),
    UOPTION_DEF(u8"extract", '\x78', UOPT_REQUIRES_ARG),

    UOPTION_DEF(u8"list", '\x6c', UOPT_NO_ARG),
    UOPTION_DEF(u8"outlist", '\x6f', UOPT_REQUIRES_ARG),

    UOPTION_DEF(u8"auto_toc_prefix", '\1', UOPT_NO_ARG),
    UOPTION_DEF(u8"auto_toc_prefix_with_type", '\1', UOPT_NO_ARG),
    UOPTION_DEF(u8"toc_prefix", '\1', UOPT_REQUIRES_ARG)
};

enum {
    OPT_HELP_H,
    OPT_HELP_QUESTION_MARK,
    OPT_OUT_TYPE,

    OPT_COPYRIGHT,
    OPT_COMMENT,

    OPT_SOURCEDIR,
    OPT_DESTDIR,

    OPT_WRITEPKG,

    OPT_MATCHMODE,

    OPT_ADD_LIST,
    OPT_REMOVE_LIST,
    OPT_EXTRACT_LIST,

    OPT_LIST_ITEMS,
    OPT_LIST_FILE,

    OPT_AUTO_TOC_PREFIX,
    OPT_AUTO_TOC_PREFIX_WITH_TYPE,
    OPT_TOC_PREFIX,

    OPT_COUNT
};

static UBool
isPackageName(const char *filename) {
    int32_t len;

    len=(int32_t)strlen(filename)-4; /* -4: subtract the length of u8".dat" */
    return (UBool)(len>0 && 0==strcmp(filename+len, u8".dat"));
}
/*
This line is required by MinGW because it incorrectly globs the arguments.
So when \* is used, it turns into a list of files instead of a literal "*"
*/
int _CRT_glob = 0;

extern int
main(int argc, char *argv[]) {
    const char *pname, *sourcePath, *destPath, *inFilename, *outFilename, *outComment;
    char outType;
    UBool isHelp, isModified, isPackage;
    int result = 0;

    Package *pkg, *listPkg, *addListPkg;

    U_MAIN_INIT_ARGS(argc, argv);

    /* get the program basename */
    pname=findBasename(argv[0]);

    argc=u_parseArgs(argc, argv, UPRV_LENGTHOF(options), options);
    isHelp=options[OPT_HELP_H].doesOccur || options[OPT_HELP_QUESTION_MARK].doesOccur;
    if(isHelp) {
        printUsage(pname, TRUE);
        return U_ZERO_ERROR;
    }


    pkg=new Package;
    if(pkg==NULL) {
        __fprintf_a(stderr, u8"icupkg: not enough memory\n");
        return U_MEMORY_ALLOCATION_ERROR;
    }
    isModified=FALSE;

    int autoPrefix=0;
    if(options[OPT_AUTO_TOC_PREFIX].doesOccur) {
        pkg->setAutoPrefix();
        ++autoPrefix;
    }
    if(options[OPT_AUTO_TOC_PREFIX_WITH_TYPE].doesOccur) {
        if(options[OPT_TOC_PREFIX].doesOccur) {
            __fprintf_a(stderr, u8"icupkg: --auto_toc_prefix_with_type and also --toc_prefix\n");
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }
        pkg->setAutoPrefixWithType();
        ++autoPrefix;
    }
    if(argc<2 || 3<argc || autoPrefix>1) {
        printUsage(pname, FALSE);
        return U_ILLEGAL_ARGUMENT_ERROR;
    }

    if(options[OPT_SOURCEDIR].doesOccur) {
        sourcePath=options[OPT_SOURCEDIR].value;
    } else {
        // work relative to the current working directory
        sourcePath=NULL;
    }
    if(options[OPT_DESTDIR].doesOccur) {
        destPath=options[OPT_DESTDIR].value;
    } else {
        // work relative to the current working directory
        destPath=NULL;
    }

    if(0==strcmp(argv[1], u8"new")) {
        if(autoPrefix) {
            __fprintf_a(stderr, u8"icupkg: --auto_toc_prefix[_with_type] but no input package\n");
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }
        inFilename=NULL;
        isPackage=TRUE;
    } else {
        inFilename=argv[1];
        if(isPackageName(inFilename)) {
            pkg->readPackage(inFilename);
            isPackage=TRUE;
        } else {
            /* swap a single file (icuswap replacement) rather than work on a package */
            pkg->addFile(sourcePath, inFilename);
            isPackage=FALSE;
        }
    }

    if(argc>=3) {
        outFilename=argv[2];
        if(0!=strcmp(argv[1], argv[2])) {
            isModified=TRUE;
        }
    } else if(isPackage) {
        outFilename=NULL;
    } else /* !isPackage */ {
        outFilename=inFilename;
        isModified=(UBool)(sourcePath!=destPath);
    }

    /* parse the output type option */
    if(options[OPT_OUT_TYPE].doesOccur) {
        const char *type=options[OPT_OUT_TYPE].value;
        if(type[0]==0 || type[1]!=0) {
            /* the type must be exactly one letter */
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }
        outType=type[0];
        switch(outType) {
        case '\x6c':
        case '\x62':
        case '\x65':
            break;
        default:
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }

        /*
         * Set the isModified flag if the output type differs from the
         * input package type.
         * If we swap a single file, just assume that we are modifying it.
         * The Package class does not give us access to the item and its type.
         */
        isModified|=(UBool)(!isPackage || outType!=pkg->getInType());
    } else if(isPackage) {
        outType=pkg->getInType(); // default to input type
    } else /* !isPackage: swap single file */ {
        outType=0; /* tells extractItem() to not swap */
    }

    if(options[OPT_WRITEPKG].doesOccur) {
        isModified=TRUE;
    }

    if(!isPackage) {
        /*
         * icuswap tool replacement: Only swap a single file.
         * Check that irrelevant options are not set.
         */
        if( options[OPT_COMMENT].doesOccur ||
            options[OPT_COPYRIGHT].doesOccur ||
            options[OPT_MATCHMODE].doesOccur ||
            options[OPT_REMOVE_LIST].doesOccur ||
            options[OPT_ADD_LIST].doesOccur ||
            options[OPT_EXTRACT_LIST].doesOccur ||
            options[OPT_LIST_ITEMS].doesOccur
        ) {
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }
        if(isModified) {
            pkg->extractItem(destPath, outFilename, 0, outType);
        }

        delete pkg;
        return result;
    }

    /* Work with a package. */

    if(options[OPT_COMMENT].doesOccur) {
        outComment=options[OPT_COMMENT].value;
    } else if(options[OPT_COPYRIGHT].doesOccur) {
        outComment=U_COPYRIGHT_STRING;
    } else {
        outComment=NULL;
    }

    if(options[OPT_MATCHMODE].doesOccur) {
        if(0==strcmp(options[OPT_MATCHMODE].value, u8"noslash")) {
            pkg->setMatchMode(Package::MATCH_NOSLASH);
        } else {
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }
    }

    /* remove items */
    if(options[OPT_REMOVE_LIST].doesOccur) {
        listPkg=new Package();
        if(listPkg==NULL) {
            __fprintf_a(stderr, u8"icupkg: not enough memory\n");
            exit(U_MEMORY_ALLOCATION_ERROR);
        }
        if(readList(NULL, options[OPT_REMOVE_LIST].value, FALSE, listPkg)) {
            pkg->removeItems(*listPkg);
            delete listPkg;
            isModified=TRUE;
        } else {
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }
    }

    /*
     * add items
     * use a separate Package so that its memory and items stay around
     * as long as the main Package
     */
    addListPkg=NULL;
    if(options[OPT_ADD_LIST].doesOccur) {
        addListPkg=new Package();
        if(addListPkg==NULL) {
            __fprintf_a(stderr, u8"icupkg: not enough memory\n");
            exit(U_MEMORY_ALLOCATION_ERROR);
        }
        if(readList(sourcePath, options[OPT_ADD_LIST].value, TRUE, addListPkg)) {
            pkg->addItems(*addListPkg);
            // delete addListPkg; deferred until after writePackage()
            isModified=TRUE;
        } else {
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }
    }

    /* extract items */
    if(options[OPT_EXTRACT_LIST].doesOccur) {
        listPkg=new Package();
        if(listPkg==NULL) {
            __fprintf_a(stderr, u8"icupkg: not enough memory\n");
            exit(U_MEMORY_ALLOCATION_ERROR);
        }
        if(readList(NULL, options[OPT_EXTRACT_LIST].value, FALSE, listPkg)) {
            pkg->extractItems(destPath, *listPkg, outType);
            delete listPkg;
        } else {
            printUsage(pname, FALSE);
            return U_ILLEGAL_ARGUMENT_ERROR;
        }
    }

    /* list items */
    if(options[OPT_LIST_ITEMS].doesOccur) {
        int32_t i;
        if (options[OPT_LIST_FILE].doesOccur) {
            FileStream *out;
            out = T_FileStream_open(options[OPT_LIST_FILE].value, u8"w");
            if (out != NULL) {
                for(i=0; i<pkg->getItemCount(); ++i) {
                    T_FileStream_writeLine(out, pkg->getItem(i)->name);
                    T_FileStream_writeLine(out, u8"\n");
                }
                T_FileStream_close(out);
            } else {
                return U_ILLEGAL_ARGUMENT_ERROR;
            }
        } else {
            for(i=0; i<pkg->getItemCount(); ++i) {
                __fprintf_a(stdout, u8"%s\n", pkg->getItem(i)->name);
            }
        }
    }

    /* check dependencies between items */
    if(!pkg->checkDependencies()) {
        /* some dependencies are not fulfilled */
        return U_MISSING_RESOURCE_ERROR;
    }

    /* write the output .dat package if there are any modifications */
    if(isModified) {
        char outFilenameBuffer[1024]; // for auto-generated output filename, if necessary

        if(outFilename==NULL || outFilename[0]==0) {
            if(inFilename==NULL || inFilename[0]==0) {
                __fprintf_a(stderr, u8"icupkg: unable to auto-generate an output filename if there is no input filename\n");
                exit(U_ILLEGAL_ARGUMENT_ERROR);
            }

            /*
             * auto-generate a filename:
             * copy the inFilename,
             * and if the last basename character matches the input file's type,
             * then replace it with the output file's type
             */
            char suffix[6]=u8"?.dat";
            char *s;

            suffix[0]=pkg->getInType();
            strcpy(outFilenameBuffer, inFilename);
            s=strchr(outFilenameBuffer, 0);
            if((s-outFilenameBuffer)>5 && 0==memcmp(s-5, suffix, 5)) {
                *(s-5)=outType;
            }
            outFilename=outFilenameBuffer;
        }
        if(options[OPT_TOC_PREFIX].doesOccur) {
            pkg->setPrefix(options[OPT_TOC_PREFIX].value);
        }
        result = writePackageDatFile(outFilename, outComment, NULL, NULL, pkg, outType);
    }

    delete addListPkg;
    delete pkg;
    return result;
}

/*
 * Hey, Emacs, please set the following:
 *
 * Local Variables:
 * indent-tabs-mode: nil
 * End:
 *
 */
