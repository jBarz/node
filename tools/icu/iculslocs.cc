#define _AE_BIMODAL
/*
**********************************************************************
*   Copyright (C) 2014, International Business Machines
*   Corporation and others.  All Rights Reserved.
**********************************************************************
*
* Created 2014-06-20 by Steven R. Loomis
*
* See: http://bugs.icu-project.org/trac/ticket/10922
*
*/

/*
WHAT IS THIS?

Here's the problem: It's difficult to reconfigure ICU from the command
line without using the full makefiles. You can do a lot, but not
everything.

Consider:

 $ icupkg -r 'ja*' icudt53l.dat

Great, you've now removed the (main) Japanese data. But something's
still wrong-- res_index (and thus, getAvailable* functions) still
claim the locale is present.

You are reading the source to a tool (using only public API C code)
that can solve this problem. Use as follows:

 $ iculslocs -i . -N icudt53l -b res_index.txt

.. Generates a NEW res_index.txt (by looking at the .dat file, and
figuring out which locales are actually available. Has commented out
the ones which are no longer available:

          ...
          it_SM {u8""}
//        ja {u8""}
//        ja_JP {u8""}
          jgo {u8""}
          ...

Then you can build and in-place patch it with existing ICU tools:
 $ genrb res_index.txt
 $ icupkg -a res_index.res icudt53l.dat

.. Now you have a patched icudt539.dat that not only doesn't have
Japanese, it doesn't *claim* to have Japanese.

*/

#include "string.h"
#include "charstr.h"  // ICU internal header
#include <unicode/ures.h>
#include <unicode/udata.h>
#include <unicode/putil.h>
#include <unistd.h>

const char* NAME = U_ICUDATA_NAME;  // assume ICU data
const char* TREE = u8"ROOT";
int VERBOSE = 1;

#define RES_INDEX u8"res_index"

CharString packageName;
const char* locale = u8"res_index";  // locale referring to our index

void usage() {
  __printf_a(u8"Usage: %s [options]\n", u8"iculslocs");
  __printf_a(
      u8"This program lists and optionally regenerates the locale "
      u8"manifests\n"
      u8" in ICU 'res_index.res' files.\n");
  __printf_a(
      u8"  -i ICUDATA  Set ICUDATA dir to ICUDATA.\n"
      u8"    NOTE: this must be the first option given.\n");
  __printf_a(u8"  -h          This Help\n");
  __printf_a(u8"  -v          Verbose Mode on\n");
  __printf_a(u8"  -l          List locales to stdout\n");
  __printf_a(
      u8"               if Verbose mode, then missing (unopenable)"
      u8"locales\n"
      u8"               will be listed preceded by a '#'.\n");
  __printf_a(
      u8"  -b res_index.txt  Write 'corrected' bundle "
      u8"to res_index.txt\n"
      u8"                    missing bundles will be "
      u8"OMITTED\n");
  __printf_a(
      u8"  -T TREE     Choose tree TREE\n"
      u8"         (TREE should be one of: \n"
      u8"    ROOT, brkitr, coll, curr, lang, rbnf, region, zone)\n");
  // see ureslocs.h and elsewhere
  __printf_a(
      u8"  -N NAME     Choose name NAME\n"
      u8"         (default: '%s')\n",
      U_ICUDATA_NAME);
  __printf_a(
      u8"\nNOTE: for best results, this tool ought to be "
      u8"linked against\n"
      u8"stubdata. i.e. '%s -l' SHOULD return an error with "
      u8" no data.\n",
      u8"iculslocs");
}

#define ASSERT_SUCCESS(status, what)      \
  if (U_FAILURE(*status)) {               \
    __printf_a(u8"%s:%d: %s: ERROR: %s %s\n", \
             __FILE__,                    \
             __LINE__,                    \
             u8"iculslocs",                        \
             u_errorName(*status),        \
             what);                       \
    return 1;                             \
  }

/**
 * @param status changed from reference to pointer to match node.js style
 */
void calculatePackageName(UErrorCode* status) {
  packageName.clear();
  if (strcmp(NAME, u8"NONE")) {
    packageName.append(NAME, *status);
    if (strcmp(TREE, u8"ROOT")) {
      packageName.append(U_TREE_SEPARATOR_STRING, *status);
      packageName.append(TREE, *status);
    }
  }
  if (VERBOSE) {
    __printf_a(u8"packageName: %s\n", packageName.data());
  }
}

/**
 * Does the locale exist?
 * return zero for false, or nonzero if it was openable.
 * Assumes calculatePackageName was called.
 * @param exists set to TRUE if exists, FALSE otherwise.
 * Changed from reference to pointer to match node.js style
 * @return 0 on u8"OK" (success or resource-missing),
 * 1 on u8"FAILURE" (unexpected error)
 */
int localeExists(const char* loc, UBool* exists) {
  UErrorCode status = U_ZERO_ERROR;
  if (VERBOSE > 1) {
    __printf_a(u8"Trying to open %s:%s\n", packageName.data(), loc);
  }
  LocalUResourceBundlePointer aResource(
      ures_openDirect(packageName.data(), loc, &status));
  *exists = FALSE;
  if (U_SUCCESS(status)) {
    *exists = true;
    if (VERBOSE > 1) {
      __printf_a(u8"%s:%s existed!\n", packageName.data(), loc);
    }
    return 0;
  } else if (status == U_MISSING_RESOURCE_ERROR) {
    *exists = false;
    if (VERBOSE > 1) {
      __printf_a(u8"%s:%s did NOT exist (%s)!\n",
             packageName.data(),
             loc,
             u_errorName(status));
    }
    return 0;  // u8"good" failure
  } else {
    // some other failure..
    __printf_a(u8"%s:%d: %s: ERROR %s opening %s for test.\n",
           __FILE__,
           __LINE__,
           u_errorName(status),
           packageName.data(),
           loc);
    return 1;  // abort
  }
}

void printIndent(FILE* bf, int indent) {
  for (int i = 0; i < indent + 1; i++) {
    __fprintf_a(bf, u8"    ");
  }
}

/**
 * Dumps a table resource contents
 * if lev==0, skips u8"InstalledLocales"
 * @return 0 for OK, 1 for err
 */
int dumpAllButInstalledLocales(int lev,
                               LocalUResourceBundlePointer* bund,
                               FILE* bf,
                               UErrorCode* status) {
  ures_resetIterator(bund->getAlias());
  LocalUResourceBundlePointer t;
  while (U_SUCCESS(*status) && ures_hasNext(bund->getAlias())) {
    t.adoptInstead(ures_getNextResource(bund->getAlias(), t.orphan(), status));
    ASSERT_SUCCESS(status, u8"while processing table");
    const char* key = ures_getKey(t.getAlias());
    if (VERBOSE > 1) {
      __printf_a(u8"dump@%d: got key %s\n", lev, key);
    }
    if (lev == 0 && !strcmp(key, u8"InstalledLocales")) {
      if (VERBOSE > 1) {
        __printf_a(u8"dump: skipping '%s' as it must be evaluated.\n", key);
      }
    } else {
      printIndent(bf, lev);
      __fprintf_a(bf, u8"%s", key);
      switch (ures_getType(t.getAlias())) {
        case URES_STRING: {
          int32_t len = 0;
          const UChar* s = ures_getString(t.getAlias(), &len, status);
          ASSERT_SUCCESS(status, u8"getting string");
          __fprintf_a(bf, u8":string {\"");
          fwrite(s, len, 1, bf);
          __fprintf_a(bf, u8"\"}");
        } break;
        default: {
          __printf_a(u8"ERROR: unhandled type in dumpAllButInstalledLocales().\n");
          return 1;
        } break;
      }
      __fprintf_a(bf, u8"\n");
    }
  }
  return 0;
}

int list(const char* toBundle) {
  UErrorCode status = U_ZERO_ERROR;

  FILE* bf = NULL;

  if (toBundle != NULL) {
    if (VERBOSE) {
      __printf_a(u8"writing to bundle %s\n", toBundle);
    }
    __a2e_s((char *)toBundle);
    bf = fopen(toBundle, "wb");
    __e2a_s((char *)toBundle);
    if (bf == NULL) {
      __printf_a(u8"ERROR: Could not open '%s' for writing.\n", toBundle);
      return 1;
    }
    __fprintf_a(bf, u8"\xEF\xBB\xBF");  // write UTF-8 BOM
    __fprintf_a(bf, u8"// -*- Coding: utf-8; -*-\n//\n");
  }

  // first, calculate the bundle name.
  calculatePackageName(&status);
  ASSERT_SUCCESS(&status, u8"calculating package name");

  if (VERBOSE) {
    __printf_a(u8"\"locale\": %s\n", locale);
  }

  LocalUResourceBundlePointer bund(
      ures_openDirect(packageName.data(), locale, &status));
  ASSERT_SUCCESS(&status, u8"while opening the bundle");
  LocalUResourceBundlePointer installedLocales(
      ures_getByKey(bund.getAlias(), u8"InstalledLocales", NULL, &status));
  ASSERT_SUCCESS(&status, u8"while fetching installed locales");

  int32_t count = ures_getSize(installedLocales.getAlias());
  if (VERBOSE) {
    __printf_a(u8"Locales: %d\n", count);
  }

  if (bf != NULL) {
    // write the HEADER
    __fprintf_a(bf,
            u8"// Warning this file is automatically generated\n"
            u8"// Updated by %s based on %s:%s.txt\n",
            u8"iculslocs",
            packageName.data(),
            locale);
    __fprintf_a(bf,
            u8"%s:table(nofallback) {\n"
            u8"    // First, everything besides InstalledLocales:\n",
            locale);
    if (dumpAllButInstalledLocales(0, &bund, bf, &status)) {
      __printf_a(u8"Error dumping prolog for %s\n", toBundle);
      fclose(bf);
      return 1;
    }
    // in case an error was missed
    ASSERT_SUCCESS(&status, u8"while writing prolog");

    __fprintf_a(bf,
            u8"    %s:table { // %d locales in input %s.res\n",
            u8"InstalledLocales",
            count,
            locale);
  }

  // OK, now list them.
  LocalUResourceBundlePointer subkey;

  int validCount = 0;
  for (int32_t i = 0; i < count; i++) {
    subkey.adoptInstead(ures_getByIndex(
        installedLocales.getAlias(), i, subkey.orphan(), &status));
    ASSERT_SUCCESS(&status, u8"while fetching an installed locale's name");

    const char* key = ures_getKey(subkey.getAlias());
    if (VERBOSE > 1) {
      __printf_a(u8"@%d: %s\n", i, key);
    }
    // now, see if the locale is installed..

    UBool exists;
    if (localeExists(key, &exists)) {
      if (bf != NULL) fclose(bf);
      return 1;  // get out.
    }
    if (exists) {
      validCount++;
      __printf_a(u8"%s\n", key);
      if (bf != NULL) {
        __fprintf_a(bf, u8"        %s {\"\"}\n", key);
      }
    } else {
      if (bf != NULL) {
        __fprintf_a(bf, u8"//      %s {\"\"}\n", key);
      }
      if (VERBOSE) {
        __printf_a(u8"#%s\n", key);  // verbosity one - '' vs '#'
      }
    }
  }

  if (bf != NULL) {
    __fprintf_a(bf, u8"    } // %d/%d valid\n", validCount, count);
    // write the HEADER
    __fprintf_a(bf, u8"}\n");
    fclose(bf);
  }

  return 0;
}

int main(int argc, const char* argv[]) {
  for (int i = 1; i < argc; i++)
      __e2a_s((char *)argv[i]);

  for (int i = 1; i < argc; i++) {
    const char* arg = argv[i];
    int argsLeft = argc - i - 1; /* how many remain? */
    if (!strcmp(arg, u8"-v")) {
      VERBOSE++;
    } else if (!strcmp(arg, u8"-i") && (argsLeft >= 1)) {
      if (i != 1) {
        __printf_a(u8"ERROR: -i must be the first argument given.\n");
        usage();
        return 1;
      }
      const char* dir = argv[++i];
      u_setDataDirectory(dir);
      if (VERBOSE) {
        __printf_a(u8"ICUDATA is now %s\n", dir);
      }
    } else if (!strcmp(arg, u8"-T") && (argsLeft >= 1)) {
      TREE = argv[++i];
      if (VERBOSE) {
        __printf_a(u8"TREE is now %s\n", TREE);
      }
    } else if (!strcmp(arg, u8"-N") && (argsLeft >= 1)) {
      NAME = argv[++i];
      if (VERBOSE) {
        __printf_a(u8"NAME is now %s\n", NAME);
      }
    } else if (!strcmp(arg, u8"-?") || !strcmp(arg, u8"-h")) {
      usage();
      return 0;
    } else if (!strcmp(arg, u8"-l")) {
      if (list(NULL)) {
        return 1;
      }
    } else if (!strcmp(arg, u8"-b") && (argsLeft >= 1)) {
      if (list(argv[++i])) {
        return 1;
      }
    } else {
      __printf_a(u8"Unknown or malformed option: %s\n", arg);
      usage();
      return 1;
    }
  }
}

// Local Variables:
// compile-command: u8"icurun iculslocs.cpp"
// End:
