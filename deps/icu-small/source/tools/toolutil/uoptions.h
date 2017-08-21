// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
*******************************************************************************
*
*   Copyright (C) 2000-2011, International Business Machines
*   Corporation and others.  All Rights Reserved.
*
*******************************************************************************
*   file name:  uoptions.h
*   encoding:   UTF-8
*   tab size:   8 (not used)
*   indentation:4
*
*   created on: 2000apr17
*   created by: Markus W. Scherer
*
*   This file provides a command line argument parser.
*/

#ifndef __UOPTIONS_H__
#define __UOPTIONS_H__

#include "unicode/utypes.h"
#define argvtoascii(argc,argv)     \
    for (int i = 0; i < argc; i++) \
        __e2a_s(argv[i])
/* This should usually be called before calling u_parseArgs */
/*#if U_PLATFORM == U_PF_OS390 && (U_CHARSET_FAMILY == U_ASCII_FAMILY)*/
    /* translate args from EBCDIC to ASCII */
/*#   define U_MAIN_INIT_ARGS(argc, argv) __argvtoascii_a(argc, argv)*/
/*#elif defined(XP_MAC_CONSOLE)*/
#if defined(XP_MAC_CONSOLE)
#   include <console.h>
    /* Get the arguments from the GUI, since old Macs don't have a console Window. */
#   define U_MAIN_INIT_ARGS(argc, argv) argc = ccommand((char***)&argv)
#else
    /* Normally we do nothing. */
#   define U_MAIN_INIT_ARGS(argc, argv) argvtoascii(argc, argv)
#endif



/* forward declarations for the function declaration */
struct UOption;
typedef struct UOption UOption;

/* function to be called for a command line option */
typedef int UOptionFn(void *context, UOption *option);

/* values of UOption.hasArg */
enum { UOPT_NO_ARG, UOPT_REQUIRES_ARG, UOPT_OPTIONAL_ARG };

/* structure describing a command line option */
struct UOption {
    const char *longName;   /* u8"foo" for --foo */
    const char *value;      /* output placeholder, will point to the argument string, if any */
    UOptionFn *optionFn;    /* function to be called when this option occurs */
    void *context;          /* parameter for the function */
    char shortName;         /* '\x66' for -f */
    char hasArg;            /* enum value: option takes no/requires/may have argument */
    char doesOccur;         /* boolean for u8"this one occured" */
};

/* macro for an entry in a declaration of UOption[] */
#define UOPTION_DEF(longName, shortName, hasArg) \
    { longName, NULL, NULL, NULL, shortName, hasArg, 0 }

/* ICU Tools option definitions */
#define UOPTION_HELP_H              UOPTION_DEF(u8"help", '\x68', UOPT_NO_ARG)
#define UOPTION_HELP_QUESTION_MARK  UOPTION_DEF(u8"help", '\x3f', UOPT_NO_ARG)
#define UOPTION_VERBOSE             UOPTION_DEF(u8"verbose", '\x76', UOPT_NO_ARG)
#define UOPTION_QUIET               UOPTION_DEF(u8"quiet", '\x71', UOPT_NO_ARG)
#define UOPTION_VERSION             UOPTION_DEF(u8"version", '\x56', UOPT_NO_ARG)
#define UOPTION_COPYRIGHT           UOPTION_DEF(u8"copyright", '\x63', UOPT_NO_ARG)

#define UOPTION_DESTDIR             UOPTION_DEF(u8"destdir", '\x64', UOPT_REQUIRES_ARG)
#define UOPTION_SOURCEDIR           UOPTION_DEF(u8"sourcedir", '\x73', UOPT_REQUIRES_ARG)
#define UOPTION_ENCODING            UOPTION_DEF(u8"encoding", '\x65', UOPT_REQUIRES_ARG)
#define UOPTION_ICUDATADIR          UOPTION_DEF(u8"icudatadir", '\x69', UOPT_REQUIRES_ARG)
#define UOPTION_WRITE_JAVA          UOPTION_DEF(u8"write-java", '\x6a', UOPT_OPTIONAL_ARG)
#define UOPTION_PACKAGE_NAME        UOPTION_DEF(u8"package-name", '\x70', UOPT_REQUIRES_ARG)
#define UOPTION_BUNDLE_NAME         UOPTION_DEF(u8"bundle-name", '\x62', UOPT_REQUIRES_ARG)

/**
 * C Command line argument parser.
 *
 * This function takes the argv[argc] command line and a description of
 * the program's options in form of an array of UOption structures.
 * Each UOption defines a long and a short name (a string and a character)
 * for options like "--foo" and "-f".
 *
 * Each option is marked with whether it does not take an argument,
 * requires one, or optionally takes one. The argument may follow in
 * the same argv[] entry for short options, or it may always follow
 * in the next argv[] entry.
 *
 * An argument is in the next argv[] entry for both long and short name
 * options, except it is taken from directly behind the short name in
 * its own argv[] entry if there are characters following the option letter.
 * An argument in its own argv[] entry must not begin with a '-'
 * unless it is only the '-' itself. There is no restriction of the
 * argument format if it is part of the short name options's argv[] entry.
 *
 * The argument is stored in the value field of the corresponding
 * UOption entry, and the doesOccur field is set to 1 if the option
 * is found at all.
 *
 * Short name options without arguments can be collapsed into a single
 * argv[] entry. After an option letter takes an argument, following
 * letters will be taken as its argument.
 *
 * If the same option is found several times, then the last
 * argument value will be stored in the value field.
 *
 * For each option, a function can be called. This could be used
 * for options that occur multiple times and all arguments are to
 * be collected.
 *
 * All options are removed from the argv[] array itself. If the parser
 * is successful, then it returns the number of remaining non-option
 * strings (including argv[0]).
 * argv[0], the program name, is never read or modified.
 *
 * An option "--" ends option processing; everything after this
 * remains in the argv[] array.
 *
 * An option string "-" alone is treated as a non-option.
 *
 * If an option is not recognized or an argument missing, then
 * the parser returns with the negative index of the argv[] entry
 * where the error was detected.
 *
 * The OS/400 compiler requires that argv either be "char* argv[]",
 * or "const char* const argv[]", and it will not accept,
 * "const char* argv[]" as a definition for main().
 *
 * @param argv This parameter is modified
 * @param options This parameter is modified
 */
U_CAPI int U_EXPORT2
u_parseArgs(int argc, char* argv[],
            int optionCount, UOption options[]);

#endif
