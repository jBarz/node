// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
********************************************************************************
*   Copyright (C) 2015, International Business Machines
*   Corporation and others.  All Rights Reserved.
********************************************************************************
*
* File decimalformatpatternimpl.h
********************************************************************************
*/

#ifndef DECIMALFORMATPATTERNIMPL_H
#define DECIMALFORMATPATTERNIMPL_H

#include "unicode/utypes.h"

#define kPatternZeroDigit            ((UChar)0x0030) /*'\x30'*/
#define kPatternSignificantDigit     ((UChar)0x0040) /*'\x40'*/
#define kPatternGroupingSeparator    ((UChar)0x002C) /*'\x2c'*/
#define kPatternDecimalSeparator     ((UChar)0x002E) /*'\x2e'*/
#define kPatternPerMill              ((UChar)0x2030)
#define kPatternPercent              ((UChar)0x0025) /*'\x25'*/
#define kPatternDigit                ((UChar)0x0023) /*'\x23'*/
#define kPatternSeparator            ((UChar)0x003B) /*'\x3b'*/
#define kPatternExponent             ((UChar)0x0045) /*'\x45'*/
#define kPatternPlus                 ((UChar)0x002B) /*'\x2b'*/
#define kPatternMinus                ((UChar)0x002D) /*'\x2d'*/
#define kPatternPadEscape            ((UChar)0x002A) /*'\x2a'*/
#define kQuote                       ((UChar)0x0027) /*'\x27'*/

#define kCurrencySign                ((UChar)0x00A4)
#define kDefaultPad                  ((UChar)0x0020) /* */

#endif
