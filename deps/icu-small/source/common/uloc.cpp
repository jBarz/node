// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
**********************************************************************
*   Copyright (C) 1997-2016, International Business Machines
*   Corporation and others.  All Rights Reserved.
**********************************************************************
*
* File ULOC.CPP
*
* Modification History:
*
*   Date        Name        Description
*   04/01/97    aliu        Creation.
*   08/21/98    stephen     JDK 1.2 sync
*   12/08/98    rtg         New Locale implementation and C API
*   03/15/99    damiba      overhaul.
*   04/06/99    stephen     changed setDefault() to realloc and copy
*   06/14/99    stephen     Changed calls to ures_open for new params
*   07/21/99    stephen     Modified setDefault() to propagate to C++
*   05/14/04    alan        7 years later: refactored, cleaned up, fixed bugs,
*                           brought canonicalization code into line with spec
*****************************************************************************/

/*
   POSIX's locale format, from putil.c: [no spaces]

     ll [ _CC ] [ . MM ] [ @ VV]

     l = lang, C = ctry, M = charmap, V = variant
*/

#include "unicode/utypes.h"
#include "unicode/ustring.h"
#include "unicode/uloc.h"

#include "putilimp.h"
#include "ustr_imp.h"
#include "ulocimp.h"
#include "umutex.h"
#include "cstring.h"
#include "cmemory.h"
#include "locmap.h"
#include "uarrsort.h"
#include "uenumimp.h"
#include "uassert.h"
#include "charstr.h"

#include <stdio.h> /* for sprintf */

U_NAMESPACE_USE

/* ### Declarations **************************************************/

/* Locale stuff from locid.cpp */
U_CFUNC void locale_set_default(const char *id);
U_CFUNC const char *locale_get_default(void);
U_CFUNC int32_t
locale_getKeywords(const char *localeID,
            char prev,
            char *keywords, int32_t keywordCapacity,
            char *values, int32_t valuesCapacity, int32_t *valLen,
            UBool valuesToo,
            UErrorCode *status);

/* ### Data tables **************************************************/

/**
 * Table of language codes, both 2- and 3-letter, with preference
 * given to 2-letter codes where possible.  Includes 3-letter codes
 * that lack a 2-letter equivalent.
 *
 * This list must be in sorted order.  This list is returned directly
 * to the user by some API.
 *
 * This list must be kept in sync with LANGUAGES_3, with corresponding
 * entries matched.
 *
 * This table should be terminated with a NULL entry, followed by a
 * second list, and another NULL entry.  The first list is visible to
 * user code when this array is returned by API.  The second list
 * contains codes we support, but do not expose through user API.
 *
 * Notes
 *
 * Tables updated per http://lcweb.loc.gov/standards/iso639-2/ to
 * include the revisions up to 2001/7/27 *CWB*
 *
 * The 3 character codes are the terminology codes like RFC 3066.  This
 * is compatible with prior ICU codes
 *
 * "in" "iw" "ji" "jw" & "sh" have been withdrawn but are still in the
 * table but now at the end of the table because 3 character codes are
 * duplicates.  This avoids bad searches going from 3 to 2 character
 * codes.
 *
 * The range qaa-qtz is reserved for local use
 */
/* Generated using org.unicode.cldr.icu.GenerateISO639LanguageTables */
/* ISO639 table version is 20150505 */
static const char * const LANGUAGES[] = {
    u8"aa",  u8"ab",  u8"ace", u8"ach", u8"ada", u8"ady", u8"ae",  u8"aeb",
    u8"af",  u8"afh", u8"agq", u8"ain", u8"ak",  u8"akk", u8"akz", u8"ale",
    u8"aln", u8"alt", u8"am",  u8"an",  u8"ang", u8"anp", u8"ar",  u8"arc",
    u8"arn", u8"aro", u8"arp", u8"arq", u8"ars", u8"arw", u8"ary", u8"arz", u8"as",
    u8"asa", u8"ase", u8"ast", u8"av",  u8"avk", u8"awa", u8"ay",  u8"az",
    u8"ba",  u8"bal", u8"ban", u8"bar", u8"bas", u8"bax", u8"bbc", u8"bbj",
    u8"be",  u8"bej", u8"bem", u8"bew", u8"bez", u8"bfd", u8"bfq", u8"bg",
    u8"bgn", u8"bho", u8"bi",  u8"bik", u8"bin", u8"bjn", u8"bkm", u8"bla",
    u8"bm",  u8"bn",  u8"bo",  u8"bpy", u8"bqi", u8"br",  u8"bra", u8"brh",
    u8"brx", u8"bs",  u8"bss", u8"bua", u8"bug", u8"bum", u8"byn", u8"byv",
    u8"ca",  u8"cad", u8"car", u8"cay", u8"cch", u8"ce",  u8"ceb", u8"cgg",
    u8"ch",  u8"chb", u8"chg", u8"chk", u8"chm", u8"chn", u8"cho", u8"chp",
    u8"chr", u8"chy", u8"ckb", u8"co",  u8"cop", u8"cps", u8"cr",  u8"crh",
    u8"cs",  u8"csb", u8"cu",  u8"cv",  u8"cy",
    u8"da",  u8"dak", u8"dar", u8"dav", u8"de",  u8"del", u8"den", u8"dgr",
    u8"din", u8"dje", u8"doi", u8"dsb", u8"dtp", u8"dua", u8"dum", u8"dv",
    u8"dyo", u8"dyu", u8"dz",  u8"dzg",
    u8"ebu", u8"ee",  u8"efi", u8"egl", u8"egy", u8"eka", u8"el",  u8"elx",
    u8"en",  u8"enm", u8"eo",  u8"es",  u8"esu", u8"et",  u8"eu",  u8"ewo",
    u8"ext",
    u8"fa",  u8"fan", u8"fat", u8"ff",  u8"fi",  u8"fil", u8"fit", u8"fj",
    u8"fo",  u8"fon", u8"fr",  u8"frc", u8"frm", u8"fro", u8"frp", u8"frr",
    u8"frs", u8"fur", u8"fy",
    u8"ga",  u8"gaa", u8"gag", u8"gan", u8"gay", u8"gba", u8"gbz", u8"gd",
    u8"gez", u8"gil", u8"gl",  u8"glk", u8"gmh", u8"gn",  u8"goh", u8"gom",
    u8"gon", u8"gor", u8"got", u8"grb", u8"grc", u8"gsw", u8"gu",  u8"guc",
    u8"gur", u8"guz", u8"gv",  u8"gwi",
    u8"ha",  u8"hai", u8"hak", u8"haw", u8"he",  u8"hi",  u8"hif", u8"hil",
    u8"hit", u8"hmn", u8"ho",  u8"hr",  u8"hsb", u8"hsn", u8"ht",  u8"hu",
    u8"hup", u8"hy",  u8"hz",
    u8"ia",  u8"iba", u8"ibb", u8"id",  u8"ie",  u8"ig",  u8"ii",  u8"ik",
    u8"ilo", u8"inh", u8"io",  u8"is",  u8"it",  u8"iu",  u8"izh",
    u8"ja",  u8"jam", u8"jbo", u8"jgo", u8"jmc", u8"jpr", u8"jrb", u8"jut",
    u8"jv",
    u8"ka",  u8"kaa", u8"kab", u8"kac", u8"kaj", u8"kam", u8"kaw", u8"kbd",
    u8"kbl", u8"kcg", u8"kde", u8"kea", u8"ken", u8"kfo", u8"kg",  u8"kgp",
    u8"kha", u8"kho", u8"khq", u8"khw", u8"ki",  u8"kiu", u8"kj",  u8"kk",
    u8"kkj", u8"kl",  u8"kln", u8"km",  u8"kmb", u8"kn",  u8"ko",  u8"koi",
    u8"kok", u8"kos", u8"kpe", u8"kr",  u8"krc", u8"kri", u8"krj", u8"krl",
    u8"kru", u8"ks",  u8"ksb", u8"ksf", u8"ksh", u8"ku",  u8"kum", u8"kut",
    u8"kv",  u8"kw",  u8"ky",
    u8"la",  u8"lad", u8"lag", u8"lah", u8"lam", u8"lb",  u8"lez", u8"lfn",
    u8"lg",  u8"li",  u8"lij", u8"liv", u8"lkt", u8"lmo", u8"ln",  u8"lo",
    u8"lol", u8"loz", u8"lrc", u8"lt",  u8"ltg", u8"lu",  u8"lua", u8"lui",
    u8"lun", u8"luo", u8"lus", u8"luy", u8"lv",  u8"lzh", u8"lzz",
    u8"mad", u8"maf", u8"mag", u8"mai", u8"mak", u8"man", u8"mas", u8"mde",
    u8"mdf", u8"mdh", u8"mdr", u8"men", u8"mer", u8"mfe", u8"mg",  u8"mga",
    u8"mgh", u8"mgo", u8"mh",  u8"mi",  u8"mic", u8"min", u8"mis", u8"mk",
    u8"ml",  u8"mn",  u8"mnc", u8"mni", u8"moh", u8"mos", u8"mr",  u8"mrj",
    u8"ms",  u8"mt",  u8"mua", u8"mul", u8"mus", u8"mwl", u8"mwr", u8"mwv",
    u8"my",  u8"mye", u8"myv", u8"mzn",
    u8"na",  u8"nan", u8"nap", u8"naq", u8"nb",  u8"nd",  u8"nds", u8"ne",
    u8"new", u8"ng",  u8"nia", u8"niu", u8"njo", u8"nl",  u8"nmg", u8"nn",
    u8"nnh", u8"no",  u8"nog", u8"non", u8"nov", u8"nqo", u8"nr",  u8"nso",
    u8"nus", u8"nv",  u8"nwc", u8"ny",  u8"nym", u8"nyn", u8"nyo", u8"nzi",
    u8"oc",  u8"oj",  u8"om",  u8"or",  u8"os",  u8"osa", u8"ota",
    u8"pa",  u8"pag", u8"pal", u8"pam", u8"pap", u8"pau", u8"pcd", u8"pdc",
    u8"pdt", u8"peo", u8"pfl", u8"phn", u8"pi",  u8"pl",  u8"pms", u8"pnt",
    u8"pon", u8"prg", u8"pro", u8"ps",  u8"pt",
    u8"qu",  u8"quc", u8"qug",
    u8"raj", u8"rap", u8"rar", u8"rgn", u8"rif", u8"rm",  u8"rn",  u8"ro",
    u8"rof", u8"rom", u8"rtm", u8"ru",  u8"rue", u8"rug", u8"rup",
    u8"rw",  u8"rwk",
    u8"sa",  u8"sad", u8"sah", u8"sam", u8"saq", u8"sas", u8"sat", u8"saz",
    u8"sba", u8"sbp", u8"sc",  u8"scn", u8"sco", u8"sd",  u8"sdc", u8"sdh",
    u8"se",  u8"see", u8"seh", u8"sei", u8"sel", u8"ses", u8"sg",  u8"sga",
    u8"sgs", u8"shi", u8"shn", u8"shu", u8"si",  u8"sid", u8"sk",
    u8"sl",  u8"sli", u8"sly", u8"sm",  u8"sma", u8"smj", u8"smn", u8"sms",
    u8"sn",  u8"snk", u8"so",  u8"sog", u8"sq",  u8"sr",  u8"srn", u8"srr",
    u8"ss",  u8"ssy", u8"st",  u8"stq", u8"su",  u8"suk", u8"sus", u8"sux",
    u8"sv",  u8"sw",  u8"swb", u8"swc", u8"syc", u8"syr", u8"szl",
    u8"ta",  u8"tcy", u8"te",  u8"tem", u8"teo", u8"ter", u8"tet", u8"tg",
    u8"th",  u8"ti",  u8"tig", u8"tiv", u8"tk",  u8"tkl", u8"tkr", u8"tl",
    u8"tlh", u8"tli", u8"tly", u8"tmh", u8"tn",  u8"to",  u8"tog", u8"tpi",
    u8"tr",  u8"tru", u8"trv", u8"ts",  u8"tsd", u8"tsi", u8"tt",  u8"ttt",
    u8"tum", u8"tvl", u8"tw",  u8"twq", u8"ty",  u8"tyv", u8"tzm",
    u8"udm", u8"ug",  u8"uga", u8"uk",  u8"umb", u8"und", u8"ur",  u8"uz",
    u8"vai", u8"ve",  u8"vec", u8"vep", u8"vi",  u8"vls", u8"vmf", u8"vo",
    u8"vot", u8"vro", u8"vun",
    u8"wa",  u8"wae", u8"wal", u8"war", u8"was", u8"wbp", u8"wo",  u8"wuu",
    u8"xal", u8"xh",  u8"xmf", u8"xog",
    u8"yao", u8"yap", u8"yav", u8"ybb", u8"yi",  u8"yo",  u8"yrl", u8"yue",
    u8"za",  u8"zap", u8"zbl", u8"zea", u8"zen", u8"zgh", u8"zh",  u8"zu",
    u8"zun", u8"zxx", u8"zza",
NULL,
    u8"in",  u8"iw",  u8"ji",  u8"jw",  u8"sh",    /* obsolete language codes */
NULL
};

static const char* const DEPRECATED_LANGUAGES[]={
    u8"in", u8"iw", u8"ji", u8"jw", NULL, NULL
};
static const char* const REPLACEMENT_LANGUAGES[]={
    u8"id", u8"he", u8"yi", u8"jv", NULL, NULL
};

/**
 * Table of 3-letter language codes.
 *
 * This is a lookup table used to convert 3-letter language codes to
 * their 2-letter equivalent, where possible.  It must be kept in sync
 * with LANGUAGES.  For all valid i, LANGUAGES[i] must refer to the
 * same language as LANGUAGES_3[i].  The commented-out lines are
 * copied from LANGUAGES to make eyeballing this baby easier.
 *
 * Where a 3-letter language code has no 2-letter equivalent, the
 * 3-letter code occupies both LANGUAGES[i] and LANGUAGES_3[i].
 *
 * This table should be terminated with a NULL entry, followed by a
 * second list, and another NULL entry.  The two lists correspond to
 * the two lists in LANGUAGES.
 */
/* Generated using org.unicode.cldr.icu.GenerateISO639LanguageTables */
/* ISO639 table version is 20150505 */
static const char * const LANGUAGES_3[] = {
    u8"aar", u8"abk", u8"ace", u8"ach", u8"ada", u8"ady", u8"ave", u8"aeb",
    u8"afr", u8"afh", u8"agq", u8"ain", u8"aka", u8"akk", u8"akz", u8"ale",
    u8"aln", u8"alt", u8"amh", u8"arg", u8"ang", u8"anp", u8"ara", u8"arc",
    u8"arn", u8"aro", u8"arp", u8"arq", u8"ars", u8"arw", u8"ary", u8"arz", u8"asm",
    u8"asa", u8"ase", u8"ast", u8"ava", u8"avk", u8"awa", u8"aym", u8"aze",
    u8"bak", u8"bal", u8"ban", u8"bar", u8"bas", u8"bax", u8"bbc", u8"bbj",
    u8"bel", u8"bej", u8"bem", u8"bew", u8"bez", u8"bfd", u8"bfq", u8"bul",
    u8"bgn", u8"bho", u8"bis", u8"bik", u8"bin", u8"bjn", u8"bkm", u8"bla",
    u8"bam", u8"ben", u8"bod", u8"bpy", u8"bqi", u8"bre", u8"bra", u8"brh",
    u8"brx", u8"bos", u8"bss", u8"bua", u8"bug", u8"bum", u8"byn", u8"byv",
    u8"cat", u8"cad", u8"car", u8"cay", u8"cch", u8"che", u8"ceb", u8"cgg",
    u8"cha", u8"chb", u8"chg", u8"chk", u8"chm", u8"chn", u8"cho", u8"chp",
    u8"chr", u8"chy", u8"ckb", u8"cos", u8"cop", u8"cps", u8"cre", u8"crh",
    u8"ces", u8"csb", u8"chu", u8"chv", u8"cym",
    u8"dan", u8"dak", u8"dar", u8"dav", u8"deu", u8"del", u8"den", u8"dgr",
    u8"din", u8"dje", u8"doi", u8"dsb", u8"dtp", u8"dua", u8"dum", u8"div",
    u8"dyo", u8"dyu", u8"dzo", u8"dzg",
    u8"ebu", u8"ewe", u8"efi", u8"egl", u8"egy", u8"eka", u8"ell", u8"elx",
    u8"eng", u8"enm", u8"epo", u8"spa", u8"esu", u8"est", u8"eus", u8"ewo",
    u8"ext",
    u8"fas", u8"fan", u8"fat", u8"ful", u8"fin", u8"fil", u8"fit", u8"fij",
    u8"fao", u8"fon", u8"fra", u8"frc", u8"frm", u8"fro", u8"frp", u8"frr",
    u8"frs", u8"fur", u8"fry",
    u8"gle", u8"gaa", u8"gag", u8"gan", u8"gay", u8"gba", u8"gbz", u8"gla",
    u8"gez", u8"gil", u8"glg", u8"glk", u8"gmh", u8"grn", u8"goh", u8"gom",
    u8"gon", u8"gor", u8"got", u8"grb", u8"grc", u8"gsw", u8"guj", u8"guc",
    u8"gur", u8"guz", u8"glv", u8"gwi",
    u8"hau", u8"hai", u8"hak", u8"haw", u8"heb", u8"hin", u8"hif", u8"hil",
    u8"hit", u8"hmn", u8"hmo", u8"hrv", u8"hsb", u8"hsn", u8"hat", u8"hun",
    u8"hup", u8"hye", u8"her",
    u8"ina", u8"iba", u8"ibb", u8"ind", u8"ile", u8"ibo", u8"iii", u8"ipk",
    u8"ilo", u8"inh", u8"ido", u8"isl", u8"ita", u8"iku", u8"izh",
    u8"jpn", u8"jam", u8"jbo", u8"jgo", u8"jmc", u8"jpr", u8"jrb", u8"jut",
    u8"jav",
    u8"kat", u8"kaa", u8"kab", u8"kac", u8"kaj", u8"kam", u8"kaw", u8"kbd",
    u8"kbl", u8"kcg", u8"kde", u8"kea", u8"ken", u8"kfo", u8"kon", u8"kgp",
    u8"kha", u8"kho", u8"khq", u8"khw", u8"kik", u8"kiu", u8"kua", u8"kaz",
    u8"kkj", u8"kal", u8"kln", u8"khm", u8"kmb", u8"kan", u8"kor", u8"koi",
    u8"kok", u8"kos", u8"kpe", u8"kau", u8"krc", u8"kri", u8"krj", u8"krl",
    u8"kru", u8"kas", u8"ksb", u8"ksf", u8"ksh", u8"kur", u8"kum", u8"kut",
    u8"kom", u8"cor", u8"kir",
    u8"lat", u8"lad", u8"lag", u8"lah", u8"lam", u8"ltz", u8"lez", u8"lfn",
    u8"lug", u8"lim", u8"lij", u8"liv", u8"lkt", u8"lmo", u8"lin", u8"lao",
    u8"lol", u8"loz", u8"lrc", u8"lit", u8"ltg", u8"lub", u8"lua", u8"lui",
    u8"lun", u8"luo", u8"lus", u8"luy", u8"lav", u8"lzh", u8"lzz",
    u8"mad", u8"maf", u8"mag", u8"mai", u8"mak", u8"man", u8"mas", u8"mde",
    u8"mdf", u8"mdh", u8"mdr", u8"men", u8"mer", u8"mfe", u8"mlg", u8"mga",
    u8"mgh", u8"mgo", u8"mah", u8"mri", u8"mic", u8"min", u8"mis", u8"mkd",
    u8"mal", u8"mon", u8"mnc", u8"mni", u8"moh", u8"mos", u8"mar", u8"mrj",
    u8"msa", u8"mlt", u8"mua", u8"mul", u8"mus", u8"mwl", u8"mwr", u8"mwv",
    u8"mya", u8"mye", u8"myv", u8"mzn",
    u8"nau", u8"nan", u8"nap", u8"naq", u8"nob", u8"nde", u8"nds", u8"nep",
    u8"new", u8"ndo", u8"nia", u8"niu", u8"njo", u8"nld", u8"nmg", u8"nno",
    u8"nnh", u8"nor", u8"nog", u8"non", u8"nov", u8"nqo", u8"nbl", u8"nso",
    u8"nus", u8"nav", u8"nwc", u8"nya", u8"nym", u8"nyn", u8"nyo", u8"nzi",
    u8"oci", u8"oji", u8"orm", u8"ori", u8"oss", u8"osa", u8"ota",
    u8"pan", u8"pag", u8"pal", u8"pam", u8"pap", u8"pau", u8"pcd", u8"pdc",
    u8"pdt", u8"peo", u8"pfl", u8"phn", u8"pli", u8"pol", u8"pms", u8"pnt",
    u8"pon", u8"prg", u8"pro", u8"pus", u8"por",
    u8"que", u8"quc", u8"qug",
    u8"raj", u8"rap", u8"rar", u8"rgn", u8"rif", u8"roh", u8"run", u8"ron",
    u8"rof", u8"rom", u8"rtm", u8"rus", u8"rue", u8"rug", u8"rup",
    u8"kin", u8"rwk",
    u8"san", u8"sad", u8"sah", u8"sam", u8"saq", u8"sas", u8"sat", u8"saz",
    u8"sba", u8"sbp", u8"srd", u8"scn", u8"sco", u8"snd", u8"sdc", u8"sdh",
    u8"sme", u8"see", u8"seh", u8"sei", u8"sel", u8"ses", u8"sag", u8"sga",
    u8"sgs", u8"shi", u8"shn", u8"shu", u8"sin", u8"sid", u8"slk",
    u8"slv", u8"sli", u8"sly", u8"smo", u8"sma", u8"smj", u8"smn", u8"sms",
    u8"sna", u8"snk", u8"som", u8"sog", u8"sqi", u8"srp", u8"srn", u8"srr",
    u8"ssw", u8"ssy", u8"sot", u8"stq", u8"sun", u8"suk", u8"sus", u8"sux",
    u8"swe", u8"swa", u8"swb", u8"swc", u8"syc", u8"syr", u8"szl",
    u8"tam", u8"tcy", u8"tel", u8"tem", u8"teo", u8"ter", u8"tet", u8"tgk",
    u8"tha", u8"tir", u8"tig", u8"tiv", u8"tuk", u8"tkl", u8"tkr", u8"tgl",
    u8"tlh", u8"tli", u8"tly", u8"tmh", u8"tsn", u8"ton", u8"tog", u8"tpi",
    u8"tur", u8"tru", u8"trv", u8"tso", u8"tsd", u8"tsi", u8"tat", u8"ttt",
    u8"tum", u8"tvl", u8"twi", u8"twq", u8"tah", u8"tyv", u8"tzm",
    u8"udm", u8"uig", u8"uga", u8"ukr", u8"umb", u8"und", u8"urd", u8"uzb",
    u8"vai", u8"ven", u8"vec", u8"vep", u8"vie", u8"vls", u8"vmf", u8"vol",
    u8"vot", u8"vro", u8"vun",
    u8"wln", u8"wae", u8"wal", u8"war", u8"was", u8"wbp", u8"wol", u8"wuu",
    u8"xal", u8"xho", u8"xmf", u8"xog",
    u8"yao", u8"yap", u8"yav", u8"ybb", u8"yid", u8"yor", u8"yrl", u8"yue",
    u8"zha", u8"zap", u8"zbl", u8"zea", u8"zen", u8"zgh", u8"zho", u8"zul",
    u8"zun", u8"zxx", u8"zza",
NULL,
/*  "in",  "iw",  "ji",  "jw",  "sh",                          */
    u8"ind", u8"heb", u8"yid", u8"jaw", u8"srp",
NULL
};

/**
 * Table of 2-letter country codes.
 *
 * This list must be in sorted order.  This list is returned directly
 * to the user by some API.
 *
 * This list must be kept in sync with COUNTRIES_3, with corresponding
 * entries matched.
 *
 * This table should be terminated with a NULL entry, followed by a
 * second list, and another NULL entry.  The first list is visible to
 * user code when this array is returned by API.  The second list
 * contains codes we support, but do not expose through user API.
 *
 * Notes:
 *
 * ZR(ZAR) is now CD(COD) and FX(FXX) is PS(PSE) as per
 * http://www.evertype.com/standards/iso3166/iso3166-1-en.html added
 * new codes keeping the old ones for compatibility updated to include
 * 1999/12/03 revisions *CWB*
 *
 * RO(ROM) is now RO(ROU) according to
 * http://www.iso.org/iso/en/prods-services/iso3166ma/03updates-on-iso-3166/nlv3e-rou.html
 */
static const char * const COUNTRIES[] = {
    u8"AD",  u8"AE",  u8"AF",  u8"AG",  u8"AI",  u8"AL",  u8"AM",
    u8"AO",  u8"AQ",  u8"AR",  u8"AS",  u8"AT",  u8"AU",  u8"AW",  u8"AX",  u8"AZ",
    u8"BA",  u8"BB",  u8"BD",  u8"BE",  u8"BF",  u8"BG",  u8"BH",  u8"BI",
    u8"BJ",  u8"BL",  u8"BM",  u8"BN",  u8"BO",  u8"BQ",  u8"BR",  u8"BS",  u8"BT",  u8"BV",
    u8"BW",  u8"BY",  u8"BZ",  u8"CA",  u8"CC",  u8"CD",  u8"CF",  u8"CG",
    u8"CH",  u8"CI",  u8"CK",  u8"CL",  u8"CM",  u8"CN",  u8"CO",  u8"CR",
    u8"CU",  u8"CV",  u8"CW",  u8"CX",  u8"CY",  u8"CZ",  u8"DE",  u8"DJ",  u8"DK",
    u8"DM",  u8"DO",  u8"DZ",  u8"EC",  u8"EE",  u8"EG",  u8"EH",  u8"ER",
    u8"ES",  u8"ET",  u8"FI",  u8"FJ",  u8"FK",  u8"FM",  u8"FO",  u8"FR",
    u8"GA",  u8"GB",  u8"GD",  u8"GE",  u8"GF",  u8"GG",  u8"GH",  u8"GI",  u8"GL",
    u8"GM",  u8"GN",  u8"GP",  u8"GQ",  u8"GR",  u8"GS",  u8"GT",  u8"GU",
    u8"GW",  u8"GY",  u8"HK",  u8"HM",  u8"HN",  u8"HR",  u8"HT",  u8"HU",
    u8"ID",  u8"IE",  u8"IL",  u8"IM",  u8"IN",  u8"IO",  u8"IQ",  u8"IR",  u8"IS",
    u8"IT",  u8"JE",  u8"JM",  u8"JO",  u8"JP",  u8"KE",  u8"KG",  u8"KH",  u8"KI",
    u8"KM",  u8"KN",  u8"KP",  u8"KR",  u8"KW",  u8"KY",  u8"KZ",  u8"LA",
    u8"LB",  u8"LC",  u8"LI",  u8"LK",  u8"LR",  u8"LS",  u8"LT",  u8"LU",
    u8"LV",  u8"LY",  u8"MA",  u8"MC",  u8"MD",  u8"ME",  u8"MF",  u8"MG",  u8"MH",  u8"MK",
    u8"ML",  u8"MM",  u8"MN",  u8"MO",  u8"MP",  u8"MQ",  u8"MR",  u8"MS",
    u8"MT",  u8"MU",  u8"MV",  u8"MW",  u8"MX",  u8"MY",  u8"MZ",  u8"NA",
    u8"NC",  u8"NE",  u8"NF",  u8"NG",  u8"NI",  u8"NL",  u8"NO",  u8"NP",
    u8"NR",  u8"NU",  u8"NZ",  u8"OM",  u8"PA",  u8"PE",  u8"PF",  u8"PG",
    u8"PH",  u8"PK",  u8"PL",  u8"PM",  u8"PN",  u8"PR",  u8"PS",  u8"PT",
    u8"PW",  u8"PY",  u8"QA",  u8"RE",  u8"RO",  u8"RS",  u8"RU",  u8"RW",  u8"SA",
    u8"SB",  u8"SC",  u8"SD",  u8"SE",  u8"SG",  u8"SH",  u8"SI",  u8"SJ",
    u8"SK",  u8"SL",  u8"SM",  u8"SN",  u8"SO",  u8"SR",  u8"SS",  u8"ST",  u8"SV",
    u8"SX",  u8"SY",  u8"SZ",  u8"TC",  u8"TD",  u8"TF",  u8"TG",  u8"TH",  u8"TJ",
    u8"TK",  u8"TL",  u8"TM",  u8"TN",  u8"TO",  u8"TR",  u8"TT",  u8"TV",
    u8"TW",  u8"TZ",  u8"UA",  u8"UG",  u8"UM",  u8"US",  u8"UY",  u8"UZ",
    u8"VA",  u8"VC",  u8"VE",  u8"VG",  u8"VI",  u8"VN",  u8"VU",  u8"WF",
    u8"WS",  u8"YE",  u8"YT",  u8"ZA",  u8"ZM",  u8"ZW",
NULL,
    u8"AN",  u8"BU", u8"CS", u8"FX", u8"RO", u8"SU", u8"TP", u8"YD", u8"YU", u8"ZR",   /* obsolete country codes */
NULL
};

static const char* const DEPRECATED_COUNTRIES[] = {
    u8"AN", u8"BU", u8"CS", u8"DD", u8"DY", u8"FX", u8"HV", u8"NH", u8"RH", u8"SU", u8"TP", u8"UK", u8"VD", u8"YD", u8"YU", u8"ZR", NULL, NULL /* deprecated country list */
};
static const char* const REPLACEMENT_COUNTRIES[] = {
/*  "AN", "BU", "CS", "DD", "DY", "FX", "HV", "NH", "RH", "SU", "TP", "UK", "VD", "YD", "YU", "ZR" */
    u8"CW", u8"MM", u8"RS", u8"DE", u8"BJ", u8"FR", u8"BF", u8"VU", u8"ZW", u8"RU", u8"TL", u8"GB", u8"VN", u8"YE", u8"RS", u8"CD", NULL, NULL  /* replacement country codes */
};

/**
 * Table of 3-letter country codes.
 *
 * This is a lookup table used to convert 3-letter country codes to
 * their 2-letter equivalent.  It must be kept in sync with COUNTRIES.
 * For all valid i, COUNTRIES[i] must refer to the same country as
 * COUNTRIES_3[i].  The commented-out lines are copied from COUNTRIES
 * to make eyeballing this baby easier.
 *
 * This table should be terminated with a NULL entry, followed by a
 * second list, and another NULL entry.  The two lists correspond to
 * the two lists in COUNTRIES.
 */
static const char * const COUNTRIES_3[] = {
/*  "AD",  "AE",  "AF",  "AG",  "AI",  "AL",  "AM",      */
    u8"AND", u8"ARE", u8"AFG", u8"ATG", u8"AIA", u8"ALB", u8"ARM",
/*  "AO",  "AQ",  "AR",  "AS",  "AT",  "AU",  "AW",  "AX",  "AZ",     */
    u8"AGO", u8"ATA", u8"ARG", u8"ASM", u8"AUT", u8"AUS", u8"ABW", u8"ALA", u8"AZE",
/*  "BA",  "BB",  "BD",  "BE",  "BF",  "BG",  "BH",  "BI",     */
    u8"BIH", u8"BRB", u8"BGD", u8"BEL", u8"BFA", u8"BGR", u8"BHR", u8"BDI",
/*  "BJ",  "BL",  "BM",  "BN",  "BO",  "BQ",  "BR",  "BS",  "BT",  "BV",     */
    u8"BEN", u8"BLM", u8"BMU", u8"BRN", u8"BOL", u8"BES", u8"BRA", u8"BHS", u8"BTN", u8"BVT",
/*  "BW",  "BY",  "BZ",  "CA",  "CC",  "CD",  "CF",  "CG",     */
    u8"BWA", u8"BLR", u8"BLZ", u8"CAN", u8"CCK", u8"COD", u8"CAF", u8"COG",
/*  "CH",  "CI",  "CK",  "CL",  "CM",  "CN",  "CO",  "CR",     */
    u8"CHE", u8"CIV", u8"COK", u8"CHL", u8"CMR", u8"CHN", u8"COL", u8"CRI",
/*  "CU",  "CV",  "CW",  "CX",  "CY",  "CZ",  "DE",  "DJ",  "DK",     */
    u8"CUB", u8"CPV", u8"CUW", u8"CXR", u8"CYP", u8"CZE", u8"DEU", u8"DJI", u8"DNK",
/*  "DM",  "DO",  "DZ",  "EC",  "EE",  "EG",  "EH",  "ER",     */
    u8"DMA", u8"DOM", u8"DZA", u8"ECU", u8"EST", u8"EGY", u8"ESH", u8"ERI",
/*  "ES",  "ET",  "FI",  "FJ",  "FK",  "FM",  "FO",  "FR",     */
    u8"ESP", u8"ETH", u8"FIN", u8"FJI", u8"FLK", u8"FSM", u8"FRO", u8"FRA",
/*  "GA",  "GB",  "GD",  "GE",  "GF",  "GG",  "GH",  "GI",  "GL",     */
    u8"GAB", u8"GBR", u8"GRD", u8"GEO", u8"GUF", u8"GGY", u8"GHA", u8"GIB", u8"GRL",
/*  "GM",  "GN",  "GP",  "GQ",  "GR",  "GS",  "GT",  "GU",     */
    u8"GMB", u8"GIN", u8"GLP", u8"GNQ", u8"GRC", u8"SGS", u8"GTM", u8"GUM",
/*  "GW",  "GY",  "HK",  "HM",  "HN",  "HR",  "HT",  "HU",     */
    u8"GNB", u8"GUY", u8"HKG", u8"HMD", u8"HND", u8"HRV", u8"HTI", u8"HUN",
/*  "ID",  "IE",  "IL",  "IM",  "IN",  "IO",  "IQ",  "IR",  "IS" */
    u8"IDN", u8"IRL", u8"ISR", u8"IMN", u8"IND", u8"IOT", u8"IRQ", u8"IRN", u8"ISL",
/*  "IT",  "JE",  "JM",  "JO",  "JP",  "KE",  "KG",  "KH",  "KI",     */
    u8"ITA", u8"JEY", u8"JAM", u8"JOR", u8"JPN", u8"KEN", u8"KGZ", u8"KHM", u8"KIR",
/*  "KM",  "KN",  "KP",  "KR",  "KW",  "KY",  "KZ",  "LA",     */
    u8"COM", u8"KNA", u8"PRK", u8"KOR", u8"KWT", u8"CYM", u8"KAZ", u8"LAO",
/*  "LB",  "LC",  "LI",  "LK",  "LR",  "LS",  "LT",  "LU",     */
    u8"LBN", u8"LCA", u8"LIE", u8"LKA", u8"LBR", u8"LSO", u8"LTU", u8"LUX",
/*  "LV",  "LY",  "MA",  "MC",  "MD",  "ME",  "MF",  "MG",  "MH",  "MK",     */
    u8"LVA", u8"LBY", u8"MAR", u8"MCO", u8"MDA", u8"MNE", u8"MAF", u8"MDG", u8"MHL", u8"MKD",
/*  "ML",  "MM",  "MN",  "MO",  "MP",  "MQ",  "MR",  "MS",     */
    u8"MLI", u8"MMR", u8"MNG", u8"MAC", u8"MNP", u8"MTQ", u8"MRT", u8"MSR",
/*  "MT",  "MU",  "MV",  "MW",  "MX",  "MY",  "MZ",  "NA",     */
    u8"MLT", u8"MUS", u8"MDV", u8"MWI", u8"MEX", u8"MYS", u8"MOZ", u8"NAM",
/*  "NC",  "NE",  "NF",  "NG",  "NI",  "NL",  "NO",  "NP",     */
    u8"NCL", u8"NER", u8"NFK", u8"NGA", u8"NIC", u8"NLD", u8"NOR", u8"NPL",
/*  "NR",  "NU",  "NZ",  "OM",  "PA",  "PE",  "PF",  "PG",     */
    u8"NRU", u8"NIU", u8"NZL", u8"OMN", u8"PAN", u8"PER", u8"PYF", u8"PNG",
/*  "PH",  "PK",  "PL",  "PM",  "PN",  "PR",  "PS",  "PT",     */
    u8"PHL", u8"PAK", u8"POL", u8"SPM", u8"PCN", u8"PRI", u8"PSE", u8"PRT",
/*  "PW",  "PY",  "QA",  "RE",  "RO",  "RS",  "RU",  "RW",  "SA",     */
    u8"PLW", u8"PRY", u8"QAT", u8"REU", u8"ROU", u8"SRB", u8"RUS", u8"RWA", u8"SAU",
/*  "SB",  "SC",  "SD",  "SE",  "SG",  "SH",  "SI",  "SJ",     */
    u8"SLB", u8"SYC", u8"SDN", u8"SWE", u8"SGP", u8"SHN", u8"SVN", u8"SJM",
/*  "SK",  "SL",  "SM",  "SN",  "SO",  "SR",  "SS",  "ST",  "SV",     */
    u8"SVK", u8"SLE", u8"SMR", u8"SEN", u8"SOM", u8"SUR", u8"SSD", u8"STP", u8"SLV",
/*  "SX",  "SY",  "SZ",  "TC",  "TD",  "TF",  "TG",  "TH",  "TJ",     */
    u8"SXM", u8"SYR", u8"SWZ", u8"TCA", u8"TCD", u8"ATF", u8"TGO", u8"THA", u8"TJK",
/*  "TK",  "TL",  "TM",  "TN",  "TO",  "TR",  "TT",  "TV",     */
    u8"TKL", u8"TLS", u8"TKM", u8"TUN", u8"TON", u8"TUR", u8"TTO", u8"TUV",
/*  "TW",  "TZ",  "UA",  "UG",  "UM",  "US",  "UY",  "UZ",     */
    u8"TWN", u8"TZA", u8"UKR", u8"UGA", u8"UMI", u8"USA", u8"URY", u8"UZB",
/*  "VA",  "VC",  "VE",  "VG",  "VI",  "VN",  "VU",  "WF",     */
    u8"VAT", u8"VCT", u8"VEN", u8"VGB", u8"VIR", u8"VNM", u8"VUT", u8"WLF",
/*  "WS",  "YE",  "YT",  "ZA",  "ZM",  "ZW",          */
    u8"WSM", u8"YEM", u8"MYT", u8"ZAF", u8"ZMB", u8"ZWE",
NULL,
/*  "AN",  "BU",  "CS",  "FX",  "RO", "SU",  "TP",  "YD",  "YU",  "ZR" */
    u8"ANT", u8"BUR", u8"SCG", u8"FXX", u8"ROM", u8"SUN", u8"TMP", u8"YMD", u8"YUG", u8"ZAR",
NULL
};

typedef struct CanonicalizationMap {
    const char *id;          /* input ID */
    const char *canonicalID; /* canonicalized output ID */
    const char *keyword;     /* keyword, or NULL if none */
    const char *value;       /* keyword value, or NULL if kw==NULL */
} CanonicalizationMap;

/**
 * A map to canonicalize locale IDs.  This handles a variety of
 * different semantic kinds of transformations.
 */
static const CanonicalizationMap CANONICALIZE_MAP[] = {
    { u8"",               u8"en_US_POSIX", NULL, NULL }, /* .NET name */
    { u8"c",              u8"en_US_POSIX", NULL, NULL }, /* POSIX name */
    { u8"posix",          u8"en_US_POSIX", NULL, NULL }, /* POSIX name (alias of C) */
    { u8"art_LOJBAN",     u8"jbo", NULL, NULL }, /* registered name */
    { u8"az_AZ_CYRL",     u8"az_Cyrl_AZ", NULL, NULL }, /* .NET name */
    { u8"az_AZ_LATN",     u8"az_Latn_AZ", NULL, NULL }, /* .NET name */
    { u8"ca_ES_PREEURO",  u8"ca_ES", u8"currency", u8"ESP" },
    { u8"de__PHONEBOOK",  u8"de", u8"collation", u8"phonebook" }, /* Old ICU name */
    { u8"de_AT_PREEURO",  u8"de_AT", u8"currency", u8"ATS" },
    { u8"de_DE_PREEURO",  u8"de_DE", u8"currency", u8"DEM" },
    { u8"de_LU_PREEURO",  u8"de_LU", u8"currency", u8"LUF" },
    { u8"el_GR_PREEURO",  u8"el_GR", u8"currency", u8"GRD" },
    { u8"en_BE_PREEURO",  u8"en_BE", u8"currency", u8"BEF" },
    { u8"en_IE_PREEURO",  u8"en_IE", u8"currency", u8"IEP" },
    { u8"es__TRADITIONAL", u8"es", u8"collation", u8"traditional" }, /* Old ICU name */
    { u8"es_ES_PREEURO",  u8"es_ES", u8"currency", u8"ESP" },
    { u8"eu_ES_PREEURO",  u8"eu_ES", u8"currency", u8"ESP" },
    { u8"fi_FI_PREEURO",  u8"fi_FI", u8"currency", u8"FIM" },
    { u8"fr_BE_PREEURO",  u8"fr_BE", u8"currency", u8"BEF" },
    { u8"fr_FR_PREEURO",  u8"fr_FR", u8"currency", u8"FRF" },
    { u8"fr_LU_PREEURO",  u8"fr_LU", u8"currency", u8"LUF" },
    { u8"ga_IE_PREEURO",  u8"ga_IE", u8"currency", u8"IEP" },
    { u8"gl_ES_PREEURO",  u8"gl_ES", u8"currency", u8"ESP" },
    { u8"hi__DIRECT",     u8"hi", u8"collation", u8"direct" }, /* Old ICU name */
    { u8"it_IT_PREEURO",  u8"it_IT", u8"currency", u8"ITL" },
    { u8"ja_JP_TRADITIONAL", u8"ja_JP", u8"calendar", u8"japanese" }, /* Old ICU name */
    { u8"nb_NO_NY",       u8"nn_NO", NULL, NULL },  /* u8"markus said this was ok" :-) */
    { u8"nl_BE_PREEURO",  u8"nl_BE", u8"currency", u8"BEF" },
    { u8"nl_NL_PREEURO",  u8"nl_NL", u8"currency", u8"NLG" },
    { u8"pt_PT_PREEURO",  u8"pt_PT", u8"currency", u8"PTE" },
    { u8"sr_SP_CYRL",     u8"sr_Cyrl_RS", NULL, NULL }, /* .NET name */
    { u8"sr_SP_LATN",     u8"sr_Latn_RS", NULL, NULL }, /* .NET name */
    { u8"sr_YU_CYRILLIC", u8"sr_Cyrl_RS", NULL, NULL }, /* Linux name */
    { u8"th_TH_TRADITIONAL", u8"th_TH", u8"calendar", u8"buddhist" }, /* Old ICU name */
    { u8"uz_UZ_CYRILLIC", u8"uz_Cyrl_UZ", NULL, NULL }, /* Linux name */
    { u8"uz_UZ_CYRL",     u8"uz_Cyrl_UZ", NULL, NULL }, /* .NET name */
    { u8"uz_UZ_LATN",     u8"uz_Latn_UZ", NULL, NULL }, /* .NET name */
    { u8"zh_CHS",         u8"zh_Hans", NULL, NULL }, /* .NET name */
    { u8"zh_CHT",         u8"zh_Hant", NULL, NULL }, /* .NET name */
    { u8"zh_GAN",         u8"gan", NULL, NULL }, /* registered name */
    { u8"zh_GUOYU",       u8"zh", NULL, NULL }, /* registered name */
    { u8"zh_HAKKA",       u8"hak", NULL, NULL }, /* registered name */
    { u8"zh_MIN_NAN",     u8"nan", NULL, NULL }, /* registered name */
    { u8"zh_WUU",         u8"wuu", NULL, NULL }, /* registered name */
    { u8"zh_XIANG",       u8"hsn", NULL, NULL }, /* registered name */
    { u8"zh_YUE",         u8"yue", NULL, NULL }, /* registered name */
};

typedef struct VariantMap {
    const char *variant;          /* input ID */
    const char *keyword;     /* keyword, or NULL if none */
    const char *value;       /* keyword value, or NULL if kw==NULL */
} VariantMap;

static const VariantMap VARIANT_MAP[] = {
    { u8"EURO",   u8"currency", u8"EUR" },
    { u8"PINYIN", u8"collation", u8"pinyin" }, /* Solaris variant */
    { u8"STROKE", u8"collation", u8"stroke" }  /* Solaris variant */
};

/* ### BCP47 Conversion *******************************************/
/* Test if the locale id has BCP47 u extension and does not have '\x40' */
#define _hasBCP47Extension(id) (id && uprv_strstr(id, u8"@") == NULL && getShortestSubtagLength(localeID) == 1)
/* Converts the BCP47 id to Unicode id. Does nothing to id if conversion fails */
#define _ConvertBCP47(finalID, id, buffer, length,err) \
        if (uloc_forLanguageTag(id, buffer, length, NULL, err) <= 0 || U_FAILURE(*err)) { \
            finalID=id; \
        } else { \
            finalID=buffer; \
        }
/* Gets the size of the shortest subtag in the given localeID. */
static int32_t getShortestSubtagLength(const char *localeID) {
    int32_t localeIDLength = uprv_strlen(localeID);
    int32_t length = localeIDLength;
    int32_t tmpLength = 0;
    int32_t i;
    UBool reset = TRUE;

    for (i = 0; i < localeIDLength; i++) {
        if (localeID[i] != '\x5f' && localeID[i] != '\x2d') {
            if (reset) {
                tmpLength = 0;
                reset = FALSE;
            }
            tmpLength++;
        } else {
            if (tmpLength != 0 && tmpLength < length) {
                length = tmpLength;
            }
            reset = TRUE;
        }
    }

    return length;
}

/* ### Keywords **************************************************/
#define UPRV_ISDIGIT(c) (((c) >= '\x30') && ((c) <= '\x39'))
#define UPRV_ISALPHANUM(c) (uprv_isASCIILetter(c) || UPRV_ISDIGIT(c) )
/* Punctuation/symbols allowed in legacy key values */
#define UPRV_OK_VALUE_PUNCTUATION(c) ((c) == '\x5f' || (c) == '\x2d' || (c) == '\x2b' || (c) == '\x2f')

#define ULOC_KEYWORD_BUFFER_LEN 25
#define ULOC_MAX_NO_KEYWORDS 25

U_CAPI const char * U_EXPORT2
locale_getKeywordsStart(const char *localeID) {
    const char *result = NULL;
    if((result = uprv_strchr(localeID, '\x40')) != NULL) {
        return result;
    }
#if (U_CHARSET_FAMILY == U_EBCDIC_FAMILY)
    else {
        /* We do this because the @ sign is variant, and the @ sign used on one
        EBCDIC machine won't be compiled the same way on other EBCDIC based
        machines. */
        static const uint8_t ebcdicSigns[] = { 0x7C, 0x44, 0x66, 0x80, 0xAC, 0xAE, 0xAF, 0xB5, 0xEC, 0xEF, 0x00 };
        const uint8_t *charToFind = ebcdicSigns;
        while(*charToFind) {
            if((result = uprv_strchr(localeID, *charToFind)) != NULL) {
                return result;
            }
            charToFind++;
        }
    }
#endif
    return NULL;
}

/**
 * @param buf buffer of size [ULOC_KEYWORD_BUFFER_LEN]
 * @param keywordName incoming name to be canonicalized
 * @param status return status (keyword too long)
 * @return length of the keyword name
 */
static int32_t locale_canonKeywordName(char *buf, const char *keywordName, UErrorCode *status)
{
  int32_t keywordNameLen = 0;

  for (; *keywordName != 0; keywordName++) {
    if (!UPRV_ISALPHANUM(*keywordName)) {
      *status = U_ILLEGAL_ARGUMENT_ERROR; /* malformed keyword name */
      return 0;
    }
    if (keywordNameLen < ULOC_KEYWORD_BUFFER_LEN - 1) {
      buf[keywordNameLen++] = uprv_tolower(*keywordName);
    } else {
      /* keyword name too long for internal buffer */
      *status = U_INTERNAL_PROGRAM_ERROR;
      return 0;
    }
  }
  if (keywordNameLen == 0) {
    *status = U_ILLEGAL_ARGUMENT_ERROR; /* empty keyword name */
    return 0;
  }
  buf[keywordNameLen] = 0; /* terminate */

  return keywordNameLen;
}

typedef struct {
    char keyword[ULOC_KEYWORD_BUFFER_LEN];
    int32_t keywordLen;
    const char *valueStart;
    int32_t valueLen;
} KeywordStruct;

static int32_t U_CALLCONV
compareKeywordStructs(const void * /*context*/, const void *left, const void *right) {
    const char* leftString = ((const KeywordStruct *)left)->keyword;
    const char* rightString = ((const KeywordStruct *)right)->keyword;
    return uprv_strcmp(leftString, rightString);
}

/**
 * Both addKeyword and addValue must already be in canonical form.
 * Either both addKeyword and addValue are NULL, or neither is NULL.
 * If they are not NULL they must be zero terminated.
 * If addKeyword is not NULL is must have length small enough to fit in KeywordStruct.keyword.
 */
static int32_t
_getKeywords(const char *localeID,
             char prev,
             char *keywords, int32_t keywordCapacity,
             char *values, int32_t valuesCapacity, int32_t *valLen,
             UBool valuesToo,
             const char* addKeyword,
             const char* addValue,
             UErrorCode *status)
{
    KeywordStruct keywordList[ULOC_MAX_NO_KEYWORDS];

    int32_t maxKeywords = ULOC_MAX_NO_KEYWORDS;
    int32_t numKeywords = 0;
    const char* pos = localeID;
    const char* equalSign = NULL;
    const char* semicolon = NULL;
    int32_t i = 0, j, n;
    int32_t keywordsLen = 0;
    int32_t valuesLen = 0;

    if(prev == '\x40') { /* start of keyword definition */
        /* we will grab pairs, trim spaces, lowercase keywords, sort and return */
        do {
            UBool duplicate = FALSE;
            /* skip leading spaces */
            while(*pos == '\x20') {
                pos++;
            }
            if (!*pos) { /* handle trailing u8"; " */
                break;
            }
            if(numKeywords == maxKeywords) {
                *status = U_INTERNAL_PROGRAM_ERROR;
                return 0;
            }
            equalSign = uprv_strchr(pos, '\x3d');
            semicolon = uprv_strchr(pos, '\x3b');
            /* lack of '=' [foo@currency] is illegal */
            /* '\x3b' before '\x3d' [foo@currency;collation=pinyin] is illegal */
            if(!equalSign || (semicolon && semicolon<equalSign)) {
                *status = U_INVALID_FORMAT_ERROR;
                return 0;
            }
            /* need to normalize both keyword and keyword name */
            if(equalSign - pos >= ULOC_KEYWORD_BUFFER_LEN) {
                /* keyword name too long for internal buffer */
                *status = U_INTERNAL_PROGRAM_ERROR;
                return 0;
            }
            for(i = 0, n = 0; i < equalSign - pos; ++i) {
                if (pos[i] != '\x20') {
                    keywordList[numKeywords].keyword[n++] = uprv_tolower(pos[i]);
                }
            }

            /* zero-length keyword is an error. */
            if (n == 0) {
                *status = U_INVALID_FORMAT_ERROR;
                return 0;
            }

            keywordList[numKeywords].keyword[n] = 0;
            keywordList[numKeywords].keywordLen = n;
            /* now grab the value part. First we skip the '=' */
            equalSign++;
            /* then we leading spaces */
            while(*equalSign == '\x20') {
                equalSign++;
            }

            /* Premature end or zero-length value */
            if (!*equalSign || equalSign == semicolon) {
                *status = U_INVALID_FORMAT_ERROR;
                return 0;
            }

            keywordList[numKeywords].valueStart = equalSign;

            pos = semicolon;
            i = 0;
            if(pos) {
                while(*(pos - i - 1) == '\x20') {
                    i++;
                }
                keywordList[numKeywords].valueLen = (int32_t)(pos - equalSign - i);
                pos++;
            } else {
                i = (int32_t)uprv_strlen(equalSign);
                while(i && equalSign[i-1] == '\x20') {
                    i--;
                }
                keywordList[numKeywords].valueLen = i;
            }
            /* If this is a duplicate keyword, then ignore it */
            for (j=0; j<numKeywords; ++j) {
                if (uprv_strcmp(keywordList[j].keyword, keywordList[numKeywords].keyword) == 0) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                ++numKeywords;
            }
        } while(pos);

        /* Handle addKeyword/addValue. */
        if (addKeyword != NULL) {
            UBool duplicate = FALSE;
            U_ASSERT(addValue != NULL);
            /* Search for duplicate; if found, do nothing. Explicit keyword
               overrides addKeyword. */
            for (j=0; j<numKeywords; ++j) {
                if (uprv_strcmp(keywordList[j].keyword, addKeyword) == 0) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                if (numKeywords == maxKeywords) {
                    *status = U_INTERNAL_PROGRAM_ERROR;
                    return 0;
                }
                uprv_strcpy(keywordList[numKeywords].keyword, addKeyword);
                keywordList[numKeywords].keywordLen = (int32_t)uprv_strlen(addKeyword);
                keywordList[numKeywords].valueStart = addValue;
                keywordList[numKeywords].valueLen = (int32_t)uprv_strlen(addValue);
                ++numKeywords;
            }
        } else {
            U_ASSERT(addValue == NULL);
        }

        /* now we have a list of keywords */
        /* we need to sort it */
        uprv_sortArray(keywordList, numKeywords, sizeof(KeywordStruct), compareKeywordStructs, NULL, FALSE, status);

        /* Now construct the keyword part */
        for(i = 0; i < numKeywords; i++) {
            if(keywordsLen + keywordList[i].keywordLen + 1< keywordCapacity) {
                uprv_strcpy(keywords+keywordsLen, keywordList[i].keyword);
                if(valuesToo) {
                    keywords[keywordsLen + keywordList[i].keywordLen] = '\x3d';
                } else {
                    keywords[keywordsLen + keywordList[i].keywordLen] = 0;
                }
            }
            keywordsLen += keywordList[i].keywordLen + 1;
            if(valuesToo) {
                if(keywordsLen + keywordList[i].valueLen < keywordCapacity) {
                    uprv_strncpy(keywords+keywordsLen, keywordList[i].valueStart, keywordList[i].valueLen);
                }
                keywordsLen += keywordList[i].valueLen;

                if(i < numKeywords - 1) {
                    if(keywordsLen < keywordCapacity) {
                        keywords[keywordsLen] = '\x3b';
                    }
                    keywordsLen++;
                }
            }
            if(values) {
                if(valuesLen + keywordList[i].valueLen + 1< valuesCapacity) {
                    uprv_strcpy(values+valuesLen, keywordList[i].valueStart);
                    values[valuesLen + keywordList[i].valueLen] = 0;
                }
                valuesLen += keywordList[i].valueLen + 1;
            }
        }
        if(values) {
            values[valuesLen] = 0;
            if(valLen) {
                *valLen = valuesLen;
            }
        }
        return u_terminateChars(keywords, keywordCapacity, keywordsLen, status);
    } else {
        return 0;
    }
}

U_CFUNC int32_t
locale_getKeywords(const char *localeID,
                   char prev,
                   char *keywords, int32_t keywordCapacity,
                   char *values, int32_t valuesCapacity, int32_t *valLen,
                   UBool valuesToo,
                   UErrorCode *status) {
    return _getKeywords(localeID, prev, keywords, keywordCapacity,
                        values, valuesCapacity, valLen, valuesToo,
                        NULL, NULL, status);
}

U_CAPI int32_t U_EXPORT2
uloc_getKeywordValue(const char* localeID,
                     const char* keywordName,
                     char* buffer, int32_t bufferCapacity,
                     UErrorCode* status)
{
    const char* startSearchHere = NULL;
    const char* nextSeparator = NULL;
    char keywordNameBuffer[ULOC_KEYWORD_BUFFER_LEN];
    char localeKeywordNameBuffer[ULOC_KEYWORD_BUFFER_LEN];
    int32_t result = 0;

    if(status && U_SUCCESS(*status) && localeID) {
      char tempBuffer[ULOC_FULLNAME_CAPACITY];
      const char* tmpLocaleID;

      if (keywordName == NULL || keywordName[0] == 0) {
        *status = U_ILLEGAL_ARGUMENT_ERROR;
        return 0;
      }

      locale_canonKeywordName(keywordNameBuffer, keywordName, status);
      if(U_FAILURE(*status)) {
        return 0;
      }

      if (_hasBCP47Extension(localeID)) {
          _ConvertBCP47(tmpLocaleID, localeID, tempBuffer, sizeof(tempBuffer), status);
      } else {
          tmpLocaleID=localeID;
      }

      startSearchHere = locale_getKeywordsStart(tmpLocaleID);
      if(startSearchHere == NULL) {
          /* no keywords, return at once */
          return 0;
      }

      /* find the first keyword */
      while(startSearchHere) {
          const char* keyValueTail;
          int32_t keyValueLen;

          startSearchHere++; /* skip @ or ; */
          nextSeparator = uprv_strchr(startSearchHere, '\x3d');
          if(!nextSeparator) {
              *status = U_ILLEGAL_ARGUMENT_ERROR; /* key must have =value */
              return 0;
          }
          /* strip leading & trailing spaces (TC decided to tolerate these) */
          while(*startSearchHere == '\x20') {
              startSearchHere++;
          }
          keyValueTail = nextSeparator;
          while (keyValueTail > startSearchHere && *(keyValueTail-1) == '\x20') {
              keyValueTail--;
          }
          /* now keyValueTail points to first char after the keyName */
          /* copy & normalize keyName from locale */
          if (startSearchHere == keyValueTail) {
              *status = U_ILLEGAL_ARGUMENT_ERROR; /* empty keyword name in passed-in locale */
              return 0;
          }
          keyValueLen = 0;
          while (startSearchHere < keyValueTail) {
            if (!UPRV_ISALPHANUM(*startSearchHere)) {
              *status = U_ILLEGAL_ARGUMENT_ERROR; /* malformed keyword name */
              return 0;
            }
            if (keyValueLen < ULOC_KEYWORD_BUFFER_LEN - 1) {
              localeKeywordNameBuffer[keyValueLen++] = uprv_tolower(*startSearchHere++);
            } else {
              /* keyword name too long for internal buffer */
              *status = U_INTERNAL_PROGRAM_ERROR;
              return 0;
            }
          }
          localeKeywordNameBuffer[keyValueLen] = 0; /* terminate */

          startSearchHere = uprv_strchr(nextSeparator, '\x3b');

          if(uprv_strcmp(keywordNameBuffer, localeKeywordNameBuffer) == 0) {
               /* current entry matches the keyword. */
             nextSeparator++; /* skip '\x3d' */
              /* First strip leading & trailing spaces (TC decided to tolerate these) */
              while(*nextSeparator == '\x20') {
                nextSeparator++;
              }
              keyValueTail = (startSearchHere)? startSearchHere: nextSeparator + uprv_strlen(nextSeparator);
              while(keyValueTail > nextSeparator && *(keyValueTail-1) == '\x20') {
                keyValueTail--;
              }
              /* Now copy the value, but check well-formedness */
              if (nextSeparator == keyValueTail) {
                *status = U_ILLEGAL_ARGUMENT_ERROR; /* empty key value name in passed-in locale */
                return 0;
              }
              keyValueLen = 0;
              while (nextSeparator < keyValueTail) {
                if (!UPRV_ISALPHANUM(*nextSeparator) && !UPRV_OK_VALUE_PUNCTUATION(*nextSeparator)) {
                  *status = U_ILLEGAL_ARGUMENT_ERROR; /* malformed key value */
                  return 0;
                }
                if (keyValueLen < bufferCapacity) {
                  /* Should we lowercase value to return here? Tests expect as-is. */
                  buffer[keyValueLen++] = *nextSeparator++;
                } else { /* keep advancing so we return correct length in case of overflow */
                  keyValueLen++;
                  nextSeparator++;
                }
              }
              result = u_terminateChars(buffer, bufferCapacity, keyValueLen, status);
              return result;
          }
      }
    }
    return 0;
}

U_CAPI int32_t U_EXPORT2
uloc_setKeywordValue(const char* keywordName,
                     const char* keywordValue,
                     char* buffer, int32_t bufferCapacity,
                     UErrorCode* status)
{
    /* TODO: sorting. removal. */
    int32_t keywordNameLen;
    int32_t keywordValueLen;
    int32_t bufLen;
    int32_t needLen = 0;
    char keywordNameBuffer[ULOC_KEYWORD_BUFFER_LEN];
    char keywordValueBuffer[ULOC_KEYWORDS_CAPACITY+1];
    char localeKeywordNameBuffer[ULOC_KEYWORD_BUFFER_LEN];
    int32_t rc;
    char* nextSeparator = NULL;
    char* nextEqualsign = NULL;
    char* startSearchHere = NULL;
    char* keywordStart = NULL;
    CharString updatedKeysAndValues;
    int32_t updatedKeysAndValuesLen;
    UBool handledInputKeyAndValue = FALSE;
    char keyValuePrefix = '\x40';

    if(U_FAILURE(*status)) {
        return -1;
    }
    if (keywordName == NULL || keywordName[0] == 0 || bufferCapacity <= 1) {
        *status = U_ILLEGAL_ARGUMENT_ERROR;
        return 0;
    }
    bufLen = (int32_t)uprv_strlen(buffer);
    if(bufferCapacity<bufLen) {
        /* The capacity is less than the length?! Is this NULL terminated? */
        *status = U_ILLEGAL_ARGUMENT_ERROR;
        return 0;
    }
    keywordNameLen = locale_canonKeywordName(keywordNameBuffer, keywordName, status);
    if(U_FAILURE(*status)) {
        return 0;
    }

    keywordValueLen = 0;
    if(keywordValue) {
        while (*keywordValue != 0) {
            if (!UPRV_ISALPHANUM(*keywordValue) && !UPRV_OK_VALUE_PUNCTUATION(*keywordValue)) {
                *status = U_ILLEGAL_ARGUMENT_ERROR; /* malformed key value */
                return 0;
            }
            if (keywordValueLen < ULOC_KEYWORDS_CAPACITY) {
                /* Should we force lowercase in value to set? */
                keywordValueBuffer[keywordValueLen++] = *keywordValue++;
            } else {
                /* keywordValue too long for internal buffer */
                *status = U_INTERNAL_PROGRAM_ERROR;
                return 0;
            }
        }
    }
    keywordValueBuffer[keywordValueLen] = 0; /* terminate */

    startSearchHere = (char*)locale_getKeywordsStart(buffer);
    if(startSearchHere == NULL || (startSearchHere[1]==0)) {
        if(keywordValueLen == 0) { /* no keywords = nothing to remove */
            return bufLen;
        }

        needLen = bufLen+1+keywordNameLen+1+keywordValueLen;
        if(startSearchHere) { /* had a single @ */
            needLen--; /* already had the @ */
            /* startSearchHere points at the @ */
        } else {
            startSearchHere=buffer+bufLen;
        }
        if(needLen >= bufferCapacity) {
            *status = U_BUFFER_OVERFLOW_ERROR;
            return needLen; /* no change */
        }
        *startSearchHere++ = '\x40';
        uprv_strcpy(startSearchHere, keywordNameBuffer);
        startSearchHere += keywordNameLen;
        *startSearchHere++ = '\x3d';
        uprv_strcpy(startSearchHere, keywordValueBuffer);
        return needLen;
    } /* end shortcut - no @ */

    keywordStart = startSearchHere;
    /* search for keyword */
    while(keywordStart) {
        const char* keyValueTail;
        int32_t keyValueLen;

        keywordStart++; /* skip @ or ; */
        nextEqualsign = uprv_strchr(keywordStart, '\x3d');
        if (!nextEqualsign) {
            *status = U_ILLEGAL_ARGUMENT_ERROR; /* key must have =value */
            return 0;
        }
        /* strip leading & trailing spaces (TC decided to tolerate these) */
        while(*keywordStart == '\x20') {
            keywordStart++;
        }
        keyValueTail = nextEqualsign;
        while (keyValueTail > keywordStart && *(keyValueTail-1) == '\x20') {
            keyValueTail--;
        }
        /* now keyValueTail points to first char after the keyName */
        /* copy & normalize keyName from locale */
        if (keywordStart == keyValueTail) {
            *status = U_ILLEGAL_ARGUMENT_ERROR; /* empty keyword name in passed-in locale */
            return 0;
        }
        keyValueLen = 0;
        while (keywordStart < keyValueTail) {
            if (!UPRV_ISALPHANUM(*keywordStart)) {
                *status = U_ILLEGAL_ARGUMENT_ERROR; /* malformed keyword name */
                return 0;
            }
            if (keyValueLen < ULOC_KEYWORD_BUFFER_LEN - 1) {
                localeKeywordNameBuffer[keyValueLen++] = uprv_tolower(*keywordStart++);
            } else {
                /* keyword name too long for internal buffer */
                *status = U_INTERNAL_PROGRAM_ERROR;
                return 0;
            }
        }
        localeKeywordNameBuffer[keyValueLen] = 0; /* terminate */

        nextSeparator = uprv_strchr(nextEqualsign, '\x3b');

        /* start processing the value part */
        nextEqualsign++; /* skip '\x3d' */
        /* First strip leading & trailing spaces (TC decided to tolerate these) */
        while(*nextEqualsign == '\x20') {
            nextEqualsign++;
        }
        keyValueTail = (nextSeparator)? nextSeparator: nextEqualsign + uprv_strlen(nextEqualsign);
        while(keyValueTail > nextEqualsign && *(keyValueTail-1) == '\x20') {
            keyValueTail--;
        }
        if (nextEqualsign == keyValueTail) {
            *status = U_ILLEGAL_ARGUMENT_ERROR; /* empty key value in passed-in locale */
            return 0;
        }

        rc = uprv_strcmp(keywordNameBuffer, localeKeywordNameBuffer);
        if(rc == 0) {
            /* Current entry matches the input keyword. Update the entry */
            if(keywordValueLen > 0) { /* updating a value */
                updatedKeysAndValues.append(keyValuePrefix, *status);
                keyValuePrefix = '\x3b'; /* for any subsequent key-value pair */
                updatedKeysAndValues.append(keywordNameBuffer, keywordNameLen, *status);
                updatedKeysAndValues.append('\x3d', *status);
                updatedKeysAndValues.append(keywordValueBuffer, keywordValueLen, *status);
            } /* else removing this entry, don't emit anything */
            handledInputKeyAndValue = TRUE;
        } else {
           /* input keyword sorts earlier than current entry, add before current entry */
            if (rc < 0 && keywordValueLen > 0 && !handledInputKeyAndValue) {
                /* insert new entry at this location */
                updatedKeysAndValues.append(keyValuePrefix, *status);
                keyValuePrefix = '\x3b'; /* for any subsequent key-value pair */
                updatedKeysAndValues.append(keywordNameBuffer, keywordNameLen, *status);
                updatedKeysAndValues.append('\x3d', *status);
                updatedKeysAndValues.append(keywordValueBuffer, keywordValueLen, *status);
                handledInputKeyAndValue = TRUE;
            }
            /* copy the current entry */
            updatedKeysAndValues.append(keyValuePrefix, *status);
            keyValuePrefix = '\x3b'; /* for any subsequent key-value pair */
            updatedKeysAndValues.append(localeKeywordNameBuffer, keyValueLen, *status);
            updatedKeysAndValues.append('\x3d', *status);
            updatedKeysAndValues.append(nextEqualsign, keyValueTail-nextEqualsign, *status);
        }
        if (!nextSeparator && keywordValueLen > 0 && !handledInputKeyAndValue) {
            /* append new entry at the end, it sorts later than existing entries */
            updatedKeysAndValues.append(keyValuePrefix, *status);
            /* skip keyValuePrefix update, no subsequent key-value pair */
            updatedKeysAndValues.append(keywordNameBuffer, keywordNameLen, *status);
            updatedKeysAndValues.append('\x3d', *status);
            updatedKeysAndValues.append(keywordValueBuffer, keywordValueLen, *status);
            handledInputKeyAndValue = TRUE;
        }
        keywordStart = nextSeparator;
    } /* end loop searching */

    /* Any error from updatedKeysAndValues.append above would be internal and not due to
     * problems with the passed-in locale. So if we did encounter problems with the
     * passed-in locale above, those errors took precedence and overrode any error
     * status from updatedKeysAndValues.append, and also caused a return of 0. If there
     * are errors here they are from updatedKeysAndValues.append; they do cause an
     * error return but the passed-in locale is unmodified and the original bufLen is
     * returned.
     */
    if (!handledInputKeyAndValue || U_FAILURE(*status)) {
        /* if input key/value specified removal of a keyword not present in locale, or
         * there was an error in CharString.append, leave original locale alone. */
        return bufLen;
    }

    updatedKeysAndValuesLen = updatedKeysAndValues.length();
    /* needLen = length of the part before '@' + length of updated key-value part including '@' */
    needLen = (int32_t)(startSearchHere - buffer) + updatedKeysAndValuesLen;
    if(needLen >= bufferCapacity) {
        *status = U_BUFFER_OVERFLOW_ERROR;
        return needLen; /* no change */
    }
    if (updatedKeysAndValuesLen > 0) {
        uprv_strncpy(startSearchHere, updatedKeysAndValues.data(), updatedKeysAndValuesLen);
    }
    buffer[needLen]=0;
    return needLen;
}

/* ### ID parsing implementation **************************************************/

#define _isPrefixLetter(a) ((a=='\x78')||(a=='\x58')||(a=='\x69')||(a=='\x49'))

/*returns TRUE if one of the special prefixes is here (s=string)
  'x-' or 'i-' */
#define _isIDPrefix(s) (_isPrefixLetter(s[0])&&_isIDSeparator(s[1]))

/* Dot terminates it because of POSIX form  where dot precedes the codepage
 * except for variant
 */
#define _isTerminator(a)  ((a==0)||(a=='\x2e')||(a=='\x40'))

static char* _strnchr(const char* str, int32_t len, char c) {
    U_ASSERT(str != 0 && len >= 0);
    while (len-- != 0) {
        char d = *str;
        if (d == c) {
            return (char*) str;
        } else if (d == 0) {
            break;
        }
        ++str;
    }
    return NULL;
}

/**
 * Lookup 'key' in the array 'list'.  The array 'list' should contain
 * a NULL entry, followed by more entries, and a second NULL entry.
 *
 * The 'list' param should be LANGUAGES, LANGUAGES_3, COUNTRIES, or
 * COUNTRIES_3.
 */
static int16_t _findIndex(const char* const* list, const char* key)
{
    const char* const* anchor = list;
    int32_t pass = 0;

    /* Make two passes through two NULL-terminated arrays at 'list' */
    while (pass++ < 2) {
        while (*list) {
            if (uprv_strcmp(key, *list) == 0) {
                return (int16_t)(list - anchor);
            }
            list++;
        }
        ++list;     /* skip final NULL *CWB*/
    }
    return -1;
}

/* count the length of src while copying it to dest; return strlen(src) */
static inline int32_t
_copyCount(char *dest, int32_t destCapacity, const char *src) {
    const char *anchor;
    char c;

    anchor=src;
    for(;;) {
        if((c=*src)==0) {
            return (int32_t)(src-anchor);
        }
        if(destCapacity<=0) {
            return (int32_t)((src-anchor)+uprv_strlen(src));
        }
        ++src;
        *dest++=c;
        --destCapacity;
    }
}

U_CFUNC const char*
uloc_getCurrentCountryID(const char* oldID){
    int32_t offset = _findIndex(DEPRECATED_COUNTRIES, oldID);
    if (offset >= 0) {
        return REPLACEMENT_COUNTRIES[offset];
    }
    return oldID;
}
U_CFUNC const char*
uloc_getCurrentLanguageID(const char* oldID){
    int32_t offset = _findIndex(DEPRECATED_LANGUAGES, oldID);
    if (offset >= 0) {
        return REPLACEMENT_LANGUAGES[offset];
    }
    return oldID;
}
/*
 * the internal functions _getLanguage(), _getCountry(), _getVariant()
 * avoid duplicating code to handle the earlier locale ID pieces
 * in the functions for the later ones by
 * setting the *pEnd pointer to where they stopped parsing
 *
 * TODO try to use this in Locale
 */
U_CFUNC int32_t
ulocimp_getLanguage(const char *localeID,
                    char *language, int32_t languageCapacity,
                    const char **pEnd) {
    int32_t i=0;
    int32_t offset;
    char lang[4]={ 0, 0, 0, 0 }; /* temporary buffer to hold language code for searching */

    /* if it starts with i- or x- then copy that prefix */
    if(_isIDPrefix(localeID)) {
        if(i<languageCapacity) {
            language[i]=(char)uprv_tolower(*localeID);
        }
        if(i<languageCapacity) {
            language[i+1]='\x2d';
        }
        i+=2;
        localeID+=2;
    }

    /* copy the language as far as possible and count its length */
    while(!_isTerminator(*localeID) && !_isIDSeparator(*localeID)) {
        if(i<languageCapacity) {
            language[i]=(char)uprv_tolower(*localeID);
        }
        if(i<3) {
            U_ASSERT(i>=0);
            lang[i]=(char)uprv_tolower(*localeID);
        }
        i++;
        localeID++;
    }

    if(i==3) {
        /* convert 3 character code to 2 character code if possible *CWB*/
        offset=_findIndex(LANGUAGES_3, lang);
        if(offset>=0) {
            i=_copyCount(language, languageCapacity, LANGUAGES[offset]);
        }
    }

    if(pEnd!=NULL) {
        *pEnd=localeID;
    }
    return i;
}

U_CFUNC int32_t
ulocimp_getScript(const char *localeID,
                  char *script, int32_t scriptCapacity,
                  const char **pEnd)
{
    int32_t idLen = 0;

    if (pEnd != NULL) {
        *pEnd = localeID;
    }

    /* copy the second item as far as possible and count its length */
    while(!_isTerminator(localeID[idLen]) && !_isIDSeparator(localeID[idLen])
            && uprv_isASCIILetter(localeID[idLen])) {
        idLen++;
    }

    /* If it's exactly 4 characters long, then it's a script and not a country. */
    if (idLen == 4) {
        int32_t i;
        if (pEnd != NULL) {
            *pEnd = localeID+idLen;
        }
        if(idLen > scriptCapacity) {
            idLen = scriptCapacity;
        }
        if (idLen >= 1) {
            script[0]=(char)uprv_toupper(*(localeID++));
        }
        for (i = 1; i < idLen; i++) {
            script[i]=(char)uprv_tolower(*(localeID++));
        }
    }
    else {
        idLen = 0;
    }
    return idLen;
}

U_CFUNC int32_t
ulocimp_getCountry(const char *localeID,
                   char *country, int32_t countryCapacity,
                   const char **pEnd)
{
    int32_t idLen=0;
    char cnty[ULOC_COUNTRY_CAPACITY]={ 0, 0, 0, 0 };
    int32_t offset;

    /* copy the country as far as possible and count its length */
    while(!_isTerminator(localeID[idLen]) && !_isIDSeparator(localeID[idLen])) {
        if(idLen<(ULOC_COUNTRY_CAPACITY-1)) {   /*CWB*/
            cnty[idLen]=(char)uprv_toupper(localeID[idLen]);
        }
        idLen++;
    }

    /* the country should be either length 2 or 3 */
    if (idLen == 2 || idLen == 3) {
        UBool gotCountry = FALSE;
        /* convert 3 character code to 2 character code if possible *CWB*/
        if(idLen==3) {
            offset=_findIndex(COUNTRIES_3, cnty);
            if(offset>=0) {
                idLen=_copyCount(country, countryCapacity, COUNTRIES[offset]);
                gotCountry = TRUE;
            }
        }
        if (!gotCountry) {
            int32_t i = 0;
            for (i = 0; i < idLen; i++) {
                if (i < countryCapacity) {
                    country[i]=(char)uprv_toupper(localeID[i]);
                }
            }
        }
        localeID+=idLen;
    } else {
        idLen = 0;
    }

    if(pEnd!=NULL) {
        *pEnd=localeID;
    }

    return idLen;
}

/**
 * @param needSeparator if true, then add leading '_' if any variants
 * are added to 'variant'
 */
static int32_t
_getVariantEx(const char *localeID,
              char prev,
              char *variant, int32_t variantCapacity,
              UBool needSeparator) {
    int32_t i=0;

    /* get one or more variant tags and separate them with '_' */
    if(_isIDSeparator(prev)) {
        /* get a variant string after a '-' or '_' */
        while(!_isTerminator(*localeID)) {
            if (needSeparator) {
                if (i<variantCapacity) {
                    variant[i] = '\x5f';
                }
                ++i;
                needSeparator = FALSE;
            }
            if(i<variantCapacity) {
                variant[i]=(char)uprv_toupper(*localeID);
                if(variant[i]=='\x2d') {
                    variant[i]='\x5f';
                }
            }
            i++;
            localeID++;
        }
    }

    /* if there is no variant tag after a '-' or '_' then look for '@' */
    if(i==0) {
        if(prev=='\x40') {
            /* keep localeID */
        } else if((localeID=locale_getKeywordsStart(localeID))!=NULL) {
            ++localeID; /* point after the '\x40' */
        } else {
            return 0;
        }
        while(!_isTerminator(*localeID)) {
            if (needSeparator) {
                if (i<variantCapacity) {
                    variant[i] = '\x5f';
                }
                ++i;
                needSeparator = FALSE;
            }
            if(i<variantCapacity) {
                variant[i]=(char)uprv_toupper(*localeID);
                if(variant[i]=='\x2d' || variant[i]=='\x2c') {
                    variant[i]='\x5f';
                }
            }
            i++;
            localeID++;
        }
    }

    return i;
}

static int32_t
_getVariant(const char *localeID,
            char prev,
            char *variant, int32_t variantCapacity) {
    return _getVariantEx(localeID, prev, variant, variantCapacity, FALSE);
}

/**
 * Delete ALL instances of a variant from the given list of one or
 * more variants.  Example: "FOO_EURO_BAR_EURO" => "FOO_BAR".
 * @param variants the source string of one or more variants,
 * separated by '_'.  This will be MODIFIED IN PLACE.  Not zero
 * terminated; if it is, trailing zero will NOT be maintained.
 * @param variantsLen length of variants
 * @param toDelete variant to delete, without separators, e.g.  "EURO"
 * or "PREEURO"; not zero terminated
 * @param toDeleteLen length of toDelete
 * @return number of characters deleted from variants
 */
static int32_t
_deleteVariant(char* variants, int32_t variantsLen,
               const char* toDelete, int32_t toDeleteLen)
{
    int32_t delta = 0; /* number of chars deleted */
    for (;;) {
        UBool flag = FALSE;
        if (variantsLen < toDeleteLen) {
            return delta;
        }
        if (uprv_strncmp(variants, toDelete, toDeleteLen) == 0 &&
            (variantsLen == toDeleteLen ||
             (flag=(variants[toDeleteLen] == '\x5f'))))
        {
            int32_t d = toDeleteLen + (flag?1:0);
            variantsLen -= d;
            delta += d;
            if (variantsLen > 0) {
                uprv_memmove(variants, variants+d, variantsLen);
            }
        } else {
            char* p = _strnchr(variants, variantsLen, '\x5f');
            if (p == NULL) {
                return delta;
            }
            ++p;
            variantsLen -= (int32_t)(p - variants);
            variants = p;
        }
    }
}

/* Keyword enumeration */

typedef struct UKeywordsContext {
    char* keywords;
    char* current;
} UKeywordsContext;

U_CDECL_BEGIN

static void U_CALLCONV
uloc_kw_closeKeywords(UEnumeration *enumerator) {
    uprv_free(((UKeywordsContext *)enumerator->context)->keywords);
    uprv_free(enumerator->context);
    uprv_free(enumerator);
}

static int32_t U_CALLCONV
uloc_kw_countKeywords(UEnumeration *en, UErrorCode * /*status*/) {
    char *kw = ((UKeywordsContext *)en->context)->keywords;
    int32_t result = 0;
    while(*kw) {
        result++;
        kw += uprv_strlen(kw)+1;
    }
    return result;
}

static const char * U_CALLCONV
uloc_kw_nextKeyword(UEnumeration* en,
                    int32_t* resultLength,
                    UErrorCode* /*status*/) {
    const char* result = ((UKeywordsContext *)en->context)->current;
    int32_t len = 0;
    if(*result) {
        len = (int32_t)uprv_strlen(((UKeywordsContext *)en->context)->current);
        ((UKeywordsContext *)en->context)->current += len+1;
    } else {
        result = NULL;
    }
    if (resultLength) {
        *resultLength = len;
    }
    return result;
}

static void U_CALLCONV
uloc_kw_resetKeywords(UEnumeration* en,
                      UErrorCode* /*status*/) {
    ((UKeywordsContext *)en->context)->current = ((UKeywordsContext *)en->context)->keywords;
}

U_CDECL_END


static const UEnumeration gKeywordsEnum = {
    NULL,
    NULL,
    uloc_kw_closeKeywords,
    uloc_kw_countKeywords,
    uenum_unextDefault,
    uloc_kw_nextKeyword,
    uloc_kw_resetKeywords
};

U_CAPI UEnumeration* U_EXPORT2
uloc_openKeywordList(const char *keywordList, int32_t keywordListSize, UErrorCode* status)
{
    UKeywordsContext *myContext = NULL;
    UEnumeration *result = NULL;

    if(U_FAILURE(*status)) {
        return NULL;
    }
    result = (UEnumeration *)uprv_malloc(sizeof(UEnumeration));
    /* Null pointer test */
    if (result == NULL) {
        *status = U_MEMORY_ALLOCATION_ERROR;
        return NULL;
    }
    uprv_memcpy(result, &gKeywordsEnum, sizeof(UEnumeration));
    myContext = static_cast<UKeywordsContext *>(uprv_malloc(sizeof(UKeywordsContext)));
    if (myContext == NULL) {
        *status = U_MEMORY_ALLOCATION_ERROR;
        uprv_free(result);
        return NULL;
    }
    myContext->keywords = (char *)uprv_malloc(keywordListSize+1);
    uprv_memcpy(myContext->keywords, keywordList, keywordListSize);
    myContext->keywords[keywordListSize] = 0;
    myContext->current = myContext->keywords;
    result->context = myContext;
    return result;
}

U_CAPI UEnumeration* U_EXPORT2
uloc_openKeywords(const char* localeID,
                        UErrorCode* status)
{
    int32_t i=0;
    char keywords[256];
    int32_t keywordsCapacity = 256;
    char tempBuffer[ULOC_FULLNAME_CAPACITY];
    const char* tmpLocaleID;

    if(status==NULL || U_FAILURE(*status)) {
        return 0;
    }

    if (_hasBCP47Extension(localeID)) {
        _ConvertBCP47(tmpLocaleID, localeID, tempBuffer, sizeof(tempBuffer), status);
    } else {
        if (localeID==NULL) {
           localeID=uloc_getDefault();
        }
        tmpLocaleID=localeID;
    }

    /* Skip the language */
    ulocimp_getLanguage(tmpLocaleID, NULL, 0, &tmpLocaleID);
    if(_isIDSeparator(*tmpLocaleID)) {
        const char *scriptID;
        /* Skip the script if available */
        ulocimp_getScript(tmpLocaleID+1, NULL, 0, &scriptID);
        if(scriptID != tmpLocaleID+1) {
            /* Found optional script */
            tmpLocaleID = scriptID;
        }
        /* Skip the Country */
        if (_isIDSeparator(*tmpLocaleID)) {
            ulocimp_getCountry(tmpLocaleID+1, NULL, 0, &tmpLocaleID);
            if(_isIDSeparator(*tmpLocaleID)) {
                _getVariant(tmpLocaleID+1, *tmpLocaleID, NULL, 0);
            }
        }
    }

    /* keywords are located after '@' */
    if((tmpLocaleID = locale_getKeywordsStart(tmpLocaleID)) != NULL) {
        i=locale_getKeywords(tmpLocaleID+1, '\x40', keywords, keywordsCapacity, NULL, 0, NULL, FALSE, status);
    }

    if(i) {
        return uloc_openKeywordList(keywords, i, status);
    } else {
        return NULL;
    }
}


/* bit-flags for 'options' parameter of _canonicalize */
#define _ULOC_STRIP_KEYWORDS 0x2
#define _ULOC_CANONICALIZE   0x1

#define OPTION_SET(options, mask) ((options & mask) != 0)

static const char i_default[] = {'\x69', '\x2d', '\x64', '\x65', '\x66', '\x61', '\x75', '\x6c', '\x74'};
#define I_DEFAULT_LENGTH UPRV_LENGTHOF(i_default)

/**
 * Canonicalize the given localeID, to level 1 or to level 2,
 * depending on the options.  To specify level 1, pass in options=0.
 * To specify level 2, pass in options=_ULOC_CANONICALIZE.
 *
 * This is the code underlying uloc_getName and uloc_canonicalize.
 */
static int32_t
_canonicalize(const char* localeID,
              char* result,
              int32_t resultCapacity,
              uint32_t options,
              UErrorCode* err) {
    int32_t j, len, fieldCount=0, scriptSize=0, variantSize=0, nameCapacity;
    char localeBuffer[ULOC_FULLNAME_CAPACITY];
    char tempBuffer[ULOC_FULLNAME_CAPACITY];
    const char* origLocaleID;
    const char* tmpLocaleID;
    const char* keywordAssign = NULL;
    const char* separatorIndicator = NULL;
    const char* addKeyword = NULL;
    const char* addValue = NULL;
    char* name;
    char* variant = NULL; /* pointer into name, or NULL */

    if (U_FAILURE(*err)) {
        return 0;
    }

    if (_hasBCP47Extension(localeID)) {
        _ConvertBCP47(tmpLocaleID, localeID, tempBuffer, sizeof(tempBuffer), err);
    } else {
        if (localeID==NULL) {
           localeID=uloc_getDefault();
        }
        tmpLocaleID=localeID;
    }

    origLocaleID=tmpLocaleID;

    /* if we are doing a full canonicalization, then put results in
       localeBuffer, if necessary; otherwise send them to result. */
    if (/*OPTION_SET(options, _ULOC_CANONICALIZE) &&*/
        (result == NULL || resultCapacity < (int32_t)sizeof(localeBuffer))) {
        name = localeBuffer;
        nameCapacity = (int32_t)sizeof(localeBuffer);
    } else {
        name = result;
        nameCapacity = resultCapacity;
    }

    /* get all pieces, one after another, and separate with '_' */
    len=ulocimp_getLanguage(tmpLocaleID, name, nameCapacity, &tmpLocaleID);

    if(len == I_DEFAULT_LENGTH && uprv_strncmp(origLocaleID, i_default, len) == 0) {
        const char *d = uloc_getDefault();

        len = (int32_t)uprv_strlen(d);

        if (name != NULL) {
            uprv_strncpy(name, d, len);
        }
    } else if(_isIDSeparator(*tmpLocaleID)) {
        const char *scriptID;

        ++fieldCount;
        if(len<nameCapacity) {
            name[len]='\x5f';
        }
        ++len;

        scriptSize=ulocimp_getScript(tmpLocaleID+1,
            (len<nameCapacity ? name+len : NULL), nameCapacity-len, &scriptID);
        if(scriptSize > 0) {
            /* Found optional script */
            tmpLocaleID = scriptID;
            ++fieldCount;
            len+=scriptSize;
            if (_isIDSeparator(*tmpLocaleID)) {
                /* If there is something else, then we add the _ */
                if(len<nameCapacity) {
                    name[len]='\x5f';
                }
                ++len;
            }
        }

        if (_isIDSeparator(*tmpLocaleID)) {
            const char *cntryID;
            int32_t cntrySize = ulocimp_getCountry(tmpLocaleID+1,
                (len<nameCapacity ? name+len : NULL), nameCapacity-len, &cntryID);
            if (cntrySize > 0) {
                /* Found optional country */
                tmpLocaleID = cntryID;
                len+=cntrySize;
            }
            if(_isIDSeparator(*tmpLocaleID)) {
                /* If there is something else, then we add the _  if we found country before. */
                if (cntrySize >= 0 && ! _isIDSeparator(*(tmpLocaleID+1)) ) {
                    ++fieldCount;
                    if(len<nameCapacity) {
                        name[len]='\x5f';
                    }
                    ++len;
                }

                variantSize = _getVariant(tmpLocaleID+1, *tmpLocaleID,
                    (len<nameCapacity ? name+len : NULL), nameCapacity-len);
                if (variantSize > 0) {
                    variant = len<nameCapacity ? name+len : NULL;
                    len += variantSize;
                    tmpLocaleID += variantSize + 1; /* skip '\x5f' and variant */
                }
            }
        }
    }

    /* Copy POSIX-style charset specifier, if any [mr.utf8] */
    if (!OPTION_SET(options, _ULOC_CANONICALIZE) && *tmpLocaleID == '\x2e') {
        UBool done = FALSE;
        do {
            char c = *tmpLocaleID;
            switch (c) {
            case 0:
            case '\x40':
                done = TRUE;
                break;
            default:
                if (len<nameCapacity) {
                    name[len] = c;
                }
                ++len;
                ++tmpLocaleID;
                break;
            }
        } while (!done);
    }

    /* Scan ahead to next '@' and determine if it is followed by '=' and/or ';'
       After this, tmpLocaleID either points to '@' or is NULL */
    if ((tmpLocaleID=locale_getKeywordsStart(tmpLocaleID))!=NULL) {
        keywordAssign = uprv_strchr(tmpLocaleID, '\x3d');
        separatorIndicator = uprv_strchr(tmpLocaleID, '\x3b');
    }

    /* Copy POSIX-style variant, if any [mr@FOO] */
    if (!OPTION_SET(options, _ULOC_CANONICALIZE) &&
        tmpLocaleID != NULL && keywordAssign == NULL) {
        for (;;) {
            char c = *tmpLocaleID;
            if (c == 0) {
                break;
            }
            if (len<nameCapacity) {
                name[len] = c;
            }
            ++len;
            ++tmpLocaleID;
        }
    }

    if (OPTION_SET(options, _ULOC_CANONICALIZE)) {
        /* Handle @FOO variant if @ is present and not followed by = */
        if (tmpLocaleID!=NULL && keywordAssign==NULL) {
            int32_t posixVariantSize;
            /* Add missing '_' if needed */
            if (fieldCount < 2 || (fieldCount < 3 && scriptSize > 0)) {
                do {
                    if(len<nameCapacity) {
                        name[len]='\x5f';
                    }
                    ++len;
                    ++fieldCount;
                } while(fieldCount<2);
            }
            posixVariantSize = _getVariantEx(tmpLocaleID+1, '\x40', name+len, nameCapacity-len,
                                             (UBool)(variantSize > 0));
            if (posixVariantSize > 0) {
                if (variant == NULL) {
                    variant = name+len;
                }
                len += posixVariantSize;
                variantSize += posixVariantSize;
            }
        }

        /* Handle generic variants first */
        if (variant) {
            for (j=0; j<UPRV_LENGTHOF(VARIANT_MAP); j++) {
                const char* variantToCompare = VARIANT_MAP[j].variant;
                int32_t n = (int32_t)uprv_strlen(variantToCompare);
                int32_t variantLen = _deleteVariant(variant, uprv_min(variantSize, (nameCapacity-len)), variantToCompare, n);
                len -= variantLen;
                if (variantLen > 0) {
                    if (len > 0 && name[len-1] == '\x5f') { /* delete trailing '\x5f' */
                        --len;
                    }
                    addKeyword = VARIANT_MAP[j].keyword;
                    addValue = VARIANT_MAP[j].value;
                    break;
                }
            }
            if (len > 0 && len <= nameCapacity && name[len-1] == '\x5f') { /* delete trailing '\x5f' */
                --len;
            }
        }

        /* Look up the ID in the canonicalization map */
        for (j=0; j<UPRV_LENGTHOF(CANONICALIZE_MAP); j++) {
            const char* id = CANONICALIZE_MAP[j].id;
            int32_t n = (int32_t)uprv_strlen(id);
            if (len == n && uprv_strncmp(name, id, n) == 0) {
                if (n == 0 && tmpLocaleID != NULL) {
                    break; /* Don't remap u8"" if keywords present */
                }
                len = _copyCount(name, nameCapacity, CANONICALIZE_MAP[j].canonicalID);
                if (CANONICALIZE_MAP[j].keyword) {
                    addKeyword = CANONICALIZE_MAP[j].keyword;
                    addValue = CANONICALIZE_MAP[j].value;
                }
                break;
            }
        }
    }

    if (!OPTION_SET(options, _ULOC_STRIP_KEYWORDS)) {
        if (tmpLocaleID!=NULL && keywordAssign!=NULL &&
            (!separatorIndicator || separatorIndicator > keywordAssign)) {
            if(len<nameCapacity) {
                name[len]='\x40';
            }
            ++len;
            ++fieldCount;
            len += _getKeywords(tmpLocaleID+1, '\x40', (len<nameCapacity ? name+len : NULL), nameCapacity-len,
                                NULL, 0, NULL, TRUE, addKeyword, addValue, err);
        } else if (addKeyword != NULL) {
            U_ASSERT(addValue != NULL && len < nameCapacity);
            /* inelegant but works -- later make _getKeywords do this? */
            len += _copyCount(name+len, nameCapacity-len, u8"@");
            len += _copyCount(name+len, nameCapacity-len, addKeyword);
            len += _copyCount(name+len, nameCapacity-len, u8"=");
            len += _copyCount(name+len, nameCapacity-len, addValue);
        }
    }

    if (U_SUCCESS(*err) && result != NULL && name == localeBuffer) {
        uprv_strncpy(result, localeBuffer, (len > resultCapacity) ? resultCapacity : len);
    }

    return u_terminateChars(result, resultCapacity, len, err);
}

/* ### ID parsing API **************************************************/

U_CAPI int32_t  U_EXPORT2
uloc_getParent(const char*    localeID,
               char* parent,
               int32_t parentCapacity,
               UErrorCode* err)
{
    const char *lastUnderscore;
    int32_t i;

    if (U_FAILURE(*err))
        return 0;

    if (localeID == NULL)
        localeID = uloc_getDefault();

    lastUnderscore=uprv_strrchr(localeID, '\x5f');
    if(lastUnderscore!=NULL) {
        i=(int32_t)(lastUnderscore-localeID);
    } else {
        i=0;
    }

    if(i>0 && parent != localeID) {
        uprv_memcpy(parent, localeID, uprv_min(i, parentCapacity));
    }
    return u_terminateChars(parent, parentCapacity, i, err);
}

U_CAPI int32_t U_EXPORT2
uloc_getLanguage(const char*    localeID,
         char* language,
         int32_t languageCapacity,
         UErrorCode* err)
{
    /* uloc_getLanguage will return a 2 character iso-639 code if one exists. *CWB*/
    int32_t i=0;

    if (err==NULL || U_FAILURE(*err)) {
        return 0;
    }

    if(localeID==NULL) {
        localeID=uloc_getDefault();
    }

    i=ulocimp_getLanguage(localeID, language, languageCapacity, NULL);
    return u_terminateChars(language, languageCapacity, i, err);
}

U_CAPI int32_t U_EXPORT2
uloc_getScript(const char*    localeID,
         char* script,
         int32_t scriptCapacity,
         UErrorCode* err)
{
    int32_t i=0;

    if(err==NULL || U_FAILURE(*err)) {
        return 0;
    }

    if(localeID==NULL) {
        localeID=uloc_getDefault();
    }

    /* skip the language */
    ulocimp_getLanguage(localeID, NULL, 0, &localeID);
    if(_isIDSeparator(*localeID)) {
        i=ulocimp_getScript(localeID+1, script, scriptCapacity, NULL);
    }
    return u_terminateChars(script, scriptCapacity, i, err);
}

U_CAPI int32_t  U_EXPORT2
uloc_getCountry(const char* localeID,
            char* country,
            int32_t countryCapacity,
            UErrorCode* err)
{
    int32_t i=0;

    if(err==NULL || U_FAILURE(*err)) {
        return 0;
    }

    if(localeID==NULL) {
        localeID=uloc_getDefault();
    }

    /* Skip the language */
    ulocimp_getLanguage(localeID, NULL, 0, &localeID);
    if(_isIDSeparator(*localeID)) {
        const char *scriptID;
        /* Skip the script if available */
        ulocimp_getScript(localeID+1, NULL, 0, &scriptID);
        if(scriptID != localeID+1) {
            /* Found optional script */
            localeID = scriptID;
        }
        if(_isIDSeparator(*localeID)) {
            i=ulocimp_getCountry(localeID+1, country, countryCapacity, NULL);
        }
    }
    return u_terminateChars(country, countryCapacity, i, err);
}

U_CAPI int32_t  U_EXPORT2
uloc_getVariant(const char* localeID,
                char* variant,
                int32_t variantCapacity,
                UErrorCode* err)
{
    char tempBuffer[ULOC_FULLNAME_CAPACITY];
    const char* tmpLocaleID;
    int32_t i=0;

    if(err==NULL || U_FAILURE(*err)) {
        return 0;
    }

    if (_hasBCP47Extension(localeID)) {
        _ConvertBCP47(tmpLocaleID, localeID, tempBuffer, sizeof(tempBuffer), err);
    } else {
        if (localeID==NULL) {
           localeID=uloc_getDefault();
        }
        tmpLocaleID=localeID;
    }

    /* Skip the language */
    ulocimp_getLanguage(tmpLocaleID, NULL, 0, &tmpLocaleID);
    if(_isIDSeparator(*tmpLocaleID)) {
        const char *scriptID;
        /* Skip the script if available */
        ulocimp_getScript(tmpLocaleID+1, NULL, 0, &scriptID);
        if(scriptID != tmpLocaleID+1) {
            /* Found optional script */
            tmpLocaleID = scriptID;
        }
        /* Skip the Country */
        if (_isIDSeparator(*tmpLocaleID)) {
            const char *cntryID;
            ulocimp_getCountry(tmpLocaleID+1, NULL, 0, &cntryID);
            if (cntryID != tmpLocaleID+1) {
                /* Found optional country */
                tmpLocaleID = cntryID;
            }
            if(_isIDSeparator(*tmpLocaleID)) {
                /* If there was no country ID, skip a possible extra IDSeparator */
                if (tmpLocaleID != cntryID && _isIDSeparator(tmpLocaleID[1])) {
                    tmpLocaleID++;
                }
                i=_getVariant(tmpLocaleID+1, *tmpLocaleID, variant, variantCapacity);
            }
        }
    }

    /* removed by weiv. We don't want to handle POSIX variants anymore. Use canonicalization function */
    /* if we do not have a variant tag yet then try a POSIX variant after '\x40' */
/*
    if(!haveVariant && (localeID=uprv_strrchr(localeID, '\x40'))!=NULL) {
        i=_getVariant(localeID+1, '\x40', variant, variantCapacity);
    }
*/
    return u_terminateChars(variant, variantCapacity, i, err);
}

U_CAPI int32_t  U_EXPORT2
uloc_getName(const char* localeID,
             char* name,
             int32_t nameCapacity,
             UErrorCode* err)
{
    return _canonicalize(localeID, name, nameCapacity, 0, err);
}

U_CAPI int32_t  U_EXPORT2
uloc_getBaseName(const char* localeID,
                 char* name,
                 int32_t nameCapacity,
                 UErrorCode* err)
{
    return _canonicalize(localeID, name, nameCapacity, _ULOC_STRIP_KEYWORDS, err);
}

U_CAPI int32_t  U_EXPORT2
uloc_canonicalize(const char* localeID,
                  char* name,
                  int32_t nameCapacity,
                  UErrorCode* err)
{
    return _canonicalize(localeID, name, nameCapacity, _ULOC_CANONICALIZE, err);
}

U_CAPI const char*  U_EXPORT2
uloc_getISO3Language(const char* localeID)
{
    int16_t offset;
    char lang[ULOC_LANG_CAPACITY];
    UErrorCode err = U_ZERO_ERROR;

    if (localeID == NULL)
    {
        localeID = uloc_getDefault();
    }
    uloc_getLanguage(localeID, lang, ULOC_LANG_CAPACITY, &err);
    if (U_FAILURE(err))
        return u8"";
    offset = _findIndex(LANGUAGES, lang);
    if (offset < 0)
        return u8"";
    return LANGUAGES_3[offset];
}

U_CAPI const char*  U_EXPORT2
uloc_getISO3Country(const char* localeID)
{
    int16_t offset;
    char cntry[ULOC_LANG_CAPACITY];
    UErrorCode err = U_ZERO_ERROR;

    if (localeID == NULL)
    {
        localeID = uloc_getDefault();
    }
    uloc_getCountry(localeID, cntry, ULOC_LANG_CAPACITY, &err);
    if (U_FAILURE(err))
        return u8"";
    offset = _findIndex(COUNTRIES, cntry);
    if (offset < 0)
        return u8"";

    return COUNTRIES_3[offset];
}

U_CAPI uint32_t  U_EXPORT2
uloc_getLCID(const char* localeID)
{
    UErrorCode status = U_ZERO_ERROR;
    char       langID[ULOC_FULLNAME_CAPACITY];
    uint32_t   lcid = 0;

    /* Check for incomplete id. */
    if (!localeID || uprv_strlen(localeID) < 2) {
        return 0;
    }

    // Attempt platform lookup if available
    lcid = uprv_convertToLCIDPlatform(localeID);
    if (lcid > 0)
    {
        // Windows found an LCID, return that
        return lcid;
    }

    uloc_getLanguage(localeID, langID, sizeof(langID), &status);
    if (U_FAILURE(status)) {
        return 0;
    }

    if (uprv_strchr(localeID, '\x40')) {
        // uprv_convertToLCID does not support keywords other than collation.
        // Remove all keywords except collation.
        int32_t len;
        char collVal[ULOC_KEYWORDS_CAPACITY];
        char tmpLocaleID[ULOC_FULLNAME_CAPACITY];

        len = uloc_getKeywordValue(localeID, u8"collation", collVal,
            UPRV_LENGTHOF(collVal) - 1, &status);

        if (U_SUCCESS(status) && len > 0) {
            collVal[len] = 0;

            len = uloc_getBaseName(localeID, tmpLocaleID,
                UPRV_LENGTHOF(tmpLocaleID) - 1, &status);

            if (U_SUCCESS(status) && len > 0) {
                tmpLocaleID[len] = 0;

                len = uloc_setKeywordValue(u8"collation", collVal, tmpLocaleID,
                    UPRV_LENGTHOF(tmpLocaleID) - len - 1, &status);

                if (U_SUCCESS(status) && len > 0) {
                    tmpLocaleID[len] = 0;
                    return uprv_convertToLCID(langID, tmpLocaleID, &status);
                }
            }
        }

        // fall through - all keywords are simply ignored
        status = U_ZERO_ERROR;
    }

    return uprv_convertToLCID(langID, localeID, &status);
}

U_CAPI int32_t U_EXPORT2
uloc_getLocaleForLCID(uint32_t hostid, char *locale, int32_t localeCapacity,
                UErrorCode *status)
{
    return uprv_convertToPosix(hostid, locale, localeCapacity, status);
}

/* ### Default locale **************************************************/

U_CAPI const char*  U_EXPORT2
uloc_getDefault()
{
    return locale_get_default();
}

U_CAPI void  U_EXPORT2
uloc_setDefault(const char*   newDefaultLocale,
             UErrorCode* err)
{
    if (U_FAILURE(*err))
        return;
    /* the error code isn't currently used for anything by this function*/

    /* propagate change to C++ */
    locale_set_default(newDefaultLocale);
}

/**
 * Returns a list of all 2-letter language codes defined in ISO 639.  This is a pointer
 * to an array of pointers to arrays of char.  All of these pointers are owned
 * by ICU-- do not delete them, and do not write through them.  The array is
 * terminated with a null pointer.
 */
U_CAPI const char* const*  U_EXPORT2
uloc_getISOLanguages()
{
    return LANGUAGES;
}

/**
 * Returns a list of all 2-letter country codes defined in ISO 639.  This is a
 * pointer to an array of pointers to arrays of char.  All of these pointers are
 * owned by ICU-- do not delete them, and do not write through them.  The array is
 * terminated with a null pointer.
 */
U_CAPI const char* const*  U_EXPORT2
uloc_getISOCountries()
{
    return COUNTRIES;
}


/* this function to be moved into cstring.c later */
static char gDecimal = 0;

static /* U_CAPI */
double
/* U_EXPORT2 */
_uloc_strtod(const char *start, char **end) {
    char *decimal;
    char *myEnd;
    char buf[30];
    double rv;
    if (!gDecimal) {
        char rep[5];
        /* For machines that decide to change the decimal on you,
        and try to be too smart with localization.
        This normally should be just a '.'. */
        sprintf(rep, u8"%+1.1f", 1.0);
        gDecimal = rep[2];
    }

    if(gDecimal == '\x2e') {
        return uprv_strtod(start, end); /* fall through to OS */
    } else {
        uprv_strncpy(buf, start, 29);
        buf[29]=0;
        decimal = uprv_strchr(buf, '\x2e');
        if(decimal) {
            *decimal = gDecimal;
        } else {
            return uprv_strtod(start, end); /* no decimal point */
        }
        rv = uprv_strtod(buf, &myEnd);
        if(end) {
            *end = (char*)(start+(myEnd-buf)); /* cast away const (to follow uprv_strtod API.) */
        }
        return rv;
    }
}

typedef struct {
    float q;
    int32_t dummy;  /* to avoid uninitialized memory copy from qsort */
    char locale[ULOC_FULLNAME_CAPACITY+1];
} _acceptLangItem;

static int32_t U_CALLCONV
uloc_acceptLanguageCompare(const void * /*context*/, const void *a, const void *b)
{
    const _acceptLangItem *aa = (const _acceptLangItem*)a;
    const _acceptLangItem *bb = (const _acceptLangItem*)b;

    int32_t rc = 0;
    if(bb->q < aa->q) {
        rc = -1;  /* A > B */
    } else if(bb->q > aa->q) {
        rc = 1;   /* A < B */
    } else {
        rc = 0;   /* A = B */
    }

    if(rc==0) {
        rc = uprv_stricmp(aa->locale, bb->locale);
    }

#if defined(ULOC_DEBUG)
    /*  fprintf(stderr, "a:[%s:%g], b:[%s:%g] -> %d\n",
    aa->locale, aa->q,
    bb->locale, bb->q,
    rc);*/
#endif

    return rc;
}

/*
mt-mt, ja;q=0.76, en-us;q=0.95, en;q=0.92, en-gb;q=0.89, fr;q=0.87, iu-ca;q=0.84, iu;q=0.82, ja-jp;q=0.79, mt;q=0.97, de-de;q=0.74, de;q=0.71, es;q=0.68, it-it;q=0.66, it;q=0.63, vi-vn;q=0.61, vi;q=0.58, nl-nl;q=0.55, nl;q=0.53
*/

U_CAPI int32_t U_EXPORT2
uloc_acceptLanguageFromHTTP(char *result, int32_t resultAvailable, UAcceptResult *outResult,
                            const char *httpAcceptLanguage,
                            UEnumeration* availableLocales,
                            UErrorCode *status)
{
  MaybeStackArray<_acceptLangItem, 4> items; // Struct for collecting items.
    char tmp[ULOC_FULLNAME_CAPACITY +1];
    int32_t n = 0;
    const char *itemEnd;
    const char *paramEnd;
    const char *s;
    const char *t;
    int32_t res;
    int32_t i;
    int32_t l = (int32_t)uprv_strlen(httpAcceptLanguage);

    if(U_FAILURE(*status)) {
        return -1;
    }

    for(s=httpAcceptLanguage;s&&*s;) {
        while(isspace(*s)) /* eat space at the beginning */
            s++;
        itemEnd=uprv_strchr(s,'\x2c');
        paramEnd=uprv_strchr(s,'\x3b');
        if(!itemEnd) {
            itemEnd = httpAcceptLanguage+l; /* end of string */
        }
        if(paramEnd && paramEnd<itemEnd) {
            /* semicolon (;) is closer than end (,) */
            t = paramEnd+1;
            if(*t=='\x71') {
                t++;
            }
            while(isspace(*t)) {
                t++;
            }
            if(*t=='\x3d') {
                t++;
            }
            while(isspace(*t)) {
                t++;
            }
            items[n].q = (float)_uloc_strtod(t,NULL);
        } else {
            /* no semicolon - it's 1.0 */
            items[n].q = 1.0f;
            paramEnd = itemEnd;
        }
        items[n].dummy=0;
        /* eat spaces prior to semi */
        for(t=(paramEnd-1);(paramEnd>s)&&isspace(*t);t--)
            ;
        int32_t slen = ((t+1)-s);
        if(slen > ULOC_FULLNAME_CAPACITY) {
          *status = U_BUFFER_OVERFLOW_ERROR;
          return -1; // too big
        }
        uprv_strncpy(items[n].locale, s, slen);
        items[n].locale[slen]=0; // terminate
        int32_t clen = uloc_canonicalize(items[n].locale, tmp, UPRV_LENGTHOF(tmp)-1, status);
        if(U_FAILURE(*status)) return -1;
        if((clen!=slen) || (uprv_strncmp(items[n].locale, tmp, slen))) {
            // canonicalization had an effect- copy back
            uprv_strncpy(items[n].locale, tmp, clen);
            items[n].locale[clen] = 0; // terminate
        }
#if defined(ULOC_DEBUG)
        /*fprintf(stderr,"%d: s <%s> q <%g>\n", n, j[n].locale, j[n].q);*/
#endif
        n++;
        s = itemEnd;
        while(*s=='\x2c') { /* eat duplicate commas */
            s++;
        }
        if(n>=items.getCapacity()) { // If we need more items
          if(NULL == items.resize(items.getCapacity()*2, items.getCapacity())) {
              *status = U_MEMORY_ALLOCATION_ERROR;
              return -1;
          }
#if defined(ULOC_DEBUG)
          fprintf(stderr,u8"malloced at size %d\n", items.getCapacity());
#endif
        }
    }
    uprv_sortArray(items.getAlias(), n, sizeof(items[0]), uloc_acceptLanguageCompare, NULL, TRUE, status);
    if (U_FAILURE(*status)) {
        return -1;
    }
    LocalMemory<const char*> strs(NULL);
    if (strs.allocateInsteadAndReset(n) == NULL) {
        *status = U_MEMORY_ALLOCATION_ERROR;
        return -1;
    }
    for(i=0;i<n;i++) {
#if defined(ULOC_DEBUG)
        /*fprintf(stderr,"%d: s <%s> q <%g>\n", i, j[i].locale, j[i].q);*/
#endif
        strs[i]=items[i].locale;
    }
    res =  uloc_acceptLanguage(result, resultAvailable, outResult,
                               strs.getAlias(), n, availableLocales, status);
    return res;
}


U_CAPI int32_t U_EXPORT2
uloc_acceptLanguage(char *result, int32_t resultAvailable,
                    UAcceptResult *outResult, const char **acceptList,
                    int32_t acceptListCount,
                    UEnumeration* availableLocales,
                    UErrorCode *status)
{
    int32_t i,j;
    int32_t len;
    int32_t maxLen=0;
    char tmp[ULOC_FULLNAME_CAPACITY+1];
    const char *l;
    char **fallbackList;
    if(U_FAILURE(*status)) {
        return -1;
    }
    fallbackList = static_cast<char **>(uprv_malloc((size_t)(sizeof(fallbackList[0])*acceptListCount)));
    if(fallbackList==NULL) {
        *status = U_MEMORY_ALLOCATION_ERROR;
        return -1;
    }
    for(i=0;i<acceptListCount;i++) {
#if defined(ULOC_DEBUG)
        fprintf(stderr,u8"%02d: %s\n", i, acceptList[i]);
#endif
        while((l=uenum_next(availableLocales, NULL, status))) {
#if defined(ULOC_DEBUG)
            fprintf(stderr,u8"  %s\n", l);
#endif
            len = (int32_t)uprv_strlen(l);
            if(!uprv_strcmp(acceptList[i], l)) {
                if(outResult) {
                    *outResult = ULOC_ACCEPT_VALID;
                }
#if defined(ULOC_DEBUG)
                fprintf(stderr, u8"MATCH! %s\n", l);
#endif
                if(len>0) {
                    uprv_strncpy(result, l, uprv_min(len, resultAvailable));
                }
                for(j=0;j<i;j++) {
                    uprv_free(fallbackList[j]);
                }
                uprv_free(fallbackList);
                return u_terminateChars(result, resultAvailable, len, status);
            }
            if(len>maxLen) {
                maxLen = len;
            }
        }
        uenum_reset(availableLocales, status);
        /* save off parent info */
        if(uloc_getParent(acceptList[i], tmp, UPRV_LENGTHOF(tmp), status)!=0) {
            fallbackList[i] = uprv_strdup(tmp);
        } else {
            fallbackList[i]=0;
        }
    }

    for(maxLen--;maxLen>0;maxLen--) {
        for(i=0;i<acceptListCount;i++) {
            if(fallbackList[i] && ((int32_t)uprv_strlen(fallbackList[i])==maxLen)) {
#if defined(ULOC_DEBUG)
                fprintf(stderr,u8"Try: [%s]", fallbackList[i]);
#endif
                while((l=uenum_next(availableLocales, NULL, status))) {
#if defined(ULOC_DEBUG)
                    fprintf(stderr,u8"  %s\n", l);
#endif
                    len = (int32_t)uprv_strlen(l);
                    if(!uprv_strcmp(fallbackList[i], l)) {
                        if(outResult) {
                            *outResult = ULOC_ACCEPT_FALLBACK;
                        }
#if defined(ULOC_DEBUG)
                        fprintf(stderr, u8"fallback MATCH! %s\n", l);
#endif
                        if(len>0) {
                            uprv_strncpy(result, l, uprv_min(len, resultAvailable));
                        }
                        for(j=0;j<acceptListCount;j++) {
                            uprv_free(fallbackList[j]);
                        }
                        uprv_free(fallbackList);
                        return u_terminateChars(result, resultAvailable, len, status);
                    }
                }
                uenum_reset(availableLocales, status);

                if(uloc_getParent(fallbackList[i], tmp, UPRV_LENGTHOF(tmp), status)!=0) {
                    uprv_free(fallbackList[i]);
                    fallbackList[i] = uprv_strdup(tmp);
                } else {
                    uprv_free(fallbackList[i]);
                    fallbackList[i]=0;
                }
            }
        }
        if(outResult) {
            *outResult = ULOC_ACCEPT_FAILED;
        }
    }
    for(i=0;i<acceptListCount;i++) {
        uprv_free(fallbackList[i]);
    }
    uprv_free(fallbackList);
    return -1;
}

U_CAPI const char* U_EXPORT2
uloc_toUnicodeLocaleKey(const char* keyword)
{
    const char* bcpKey = ulocimp_toBcpKey(keyword);
    if (bcpKey == NULL && ultag_isUnicodeLocaleKey(keyword, -1)) {
        // unknown keyword, but syntax is fine..
        return keyword;
    }
    return bcpKey;
}

U_CAPI const char* U_EXPORT2
uloc_toUnicodeLocaleType(const char* keyword, const char* value)
{
    const char* bcpType = ulocimp_toBcpType(keyword, value, NULL, NULL);
    if (bcpType == NULL && ultag_isUnicodeLocaleType(value, -1)) {
        // unknown keyword, but syntax is fine..
        return value;
    }
    return bcpType;
}

static UBool
isWellFormedLegacyKey(const char* legacyKey)
{
    const char* p = legacyKey;
    while (*p) {
        if (!UPRV_ISALPHANUM(*p)) {
            return FALSE;
        }
        p++;
    }
    return TRUE;
}

static UBool
isWellFormedLegacyType(const char* legacyType)
{
    const char* p = legacyType;
    int32_t alphaNumLen = 0;
    while (*p) {
        if (*p == '\x5f' || *p == '\x2f' || *p == '\x2d') {
            if (alphaNumLen == 0) {
                return FALSE;
            }
            alphaNumLen = 0;
        } else if (UPRV_ISALPHANUM(*p)) {
            alphaNumLen++;
        } else {
            return FALSE;
        }
        p++;
    }
    return (alphaNumLen != 0);
}

U_CAPI const char* U_EXPORT2
uloc_toLegacyKey(const char* keyword)
{
    const char* legacyKey = ulocimp_toLegacyKey(keyword);
    if (legacyKey == NULL) {
        // Checks if the specified locale key is well-formed with the legacy locale syntax.
        //
        // Note:
        //  LDML/CLDR provides some definition of keyword syntax in
        //  * http://www.unicode.org/reports/tr35/#Unicode_locale_identifier and
        //  * http://www.unicode.org/reports/tr35/#Old_Locale_Extension_Syntax
        //  Keys can only consist of [0-9a-zA-Z].
        if (isWellFormedLegacyKey(keyword)) {
            return keyword;
        }
    }
    return legacyKey;
}

U_CAPI const char* U_EXPORT2
uloc_toLegacyType(const char* keyword, const char* value)
{
    const char* legacyType = ulocimp_toLegacyType(keyword, value, NULL, NULL);
    if (legacyType == NULL) {
        // Checks if the specified locale type is well-formed with the legacy locale syntax.
        //
        // Note:
        //  LDML/CLDR provides some definition of keyword syntax in
        //  * http://www.unicode.org/reports/tr35/#Unicode_locale_identifier and
        //  * http://www.unicode.org/reports/tr35/#Old_Locale_Extension_Syntax
        //  Values (types) can only consist of [0-9a-zA-Z], plus for legacy values
        //  we allow [/_-+] in the middle (e.g. "Etc/GMT+1", "Asia/Tel_Aviv")
        if (isWellFormedLegacyType(value)) {
            return value;
        }
    }
    return legacyType;
}

/*eof*/
