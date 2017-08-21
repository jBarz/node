// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
**********************************************************************
*   Copyright (C) 2009-2014 International Business Machines
*   Corporation and others.  All Rights Reserved.
**********************************************************************
*/

#ifndef __URESLOCS_H__
#define __URESLOCS_H__

#include "unicode/utypes.h"
#include "unicode/udata.h"

U_CDECL_BEGIN


#define U_ICUDATA_LANG U_ICUDATA_NAME U_TREE_SEPARATOR_STRING u8"lang"
#define U_ICUDATA_REGION U_ICUDATA_NAME U_TREE_SEPARATOR_STRING u8"region"
#define U_ICUDATA_CURR U_ICUDATA_NAME U_TREE_SEPARATOR_STRING u8"curr"
#define U_ICUDATA_ZONE U_ICUDATA_NAME U_TREE_SEPARATOR_STRING u8"zone"
#define U_ICUDATA_UNIT U_ICUDATA_NAME U_TREE_SEPARATOR_STRING u8"unit"

U_CDECL_END

#endif
