#ifndef SRC_NODE_VERSION_H_
#define SRC_NODE_VERSION_H_

#define NODE_MAJOR_VERSION 6
#define NODE_MINOR_VERSION 10
#define NODE_PATCH_VERSION 3

#define NODE_VERSION_IS_LTS 1
#define NODE_VERSION_LTS_CODENAME "\x42\x6f\x72\x6f\x6e"

#define NODE_VERSION_IS_RELEASE 1

#ifndef NODE_STRINGIFY
#define USTR(x) u8##x
#define NODE_STRINGIFY(n) NODE_STRINGIFY_HELPER(n)
#define NODE_STRINGIFY_HELPER(n) USTR(#n)
#endif

#ifndef NODE_TAG
# if NODE_VERSION_IS_RELEASE
#  define NODE_TAG ""
# else
#  define NODE_TAG "\x2d\x70\x72\x65"
# endif
#else
// NODE_TAG is passed without quotes when rc.exe is run from msbuild
# define NODE_EXE_VERSION NODE_STRINGIFY(NODE_MAJOR_VERSION) "\x2e" \
                          NODE_STRINGIFY(NODE_MINOR_VERSION) "\x2e" \
                          NODE_STRINGIFY(NODE_PATCH_VERSION)     \
                          NODE_STRINGIFY(NODE_TAG)
#endif

# define NODE_VERSION_STRING  NODE_STRINGIFY(NODE_MAJOR_VERSION) "\x2e" \
                              NODE_STRINGIFY(NODE_MINOR_VERSION) "\x2e" \
                              NODE_STRINGIFY(NODE_PATCH_VERSION)
#ifndef NODE_EXE_VERSION
# define NODE_EXE_VERSION NODE_VERSION_STRING
#endif

#define NODE_VERSION "\x76" NODE_VERSION_STRING


#define NODE_VERSION_AT_LEAST(major, minor, patch) \
  (( (major) < NODE_MAJOR_VERSION) \
  || ((major) == NODE_MAJOR_VERSION && (minor) < NODE_MINOR_VERSION) \
  || ((major) == NODE_MAJOR_VERSION && \
      (minor) == NODE_MINOR_VERSION && (patch) <= NODE_PATCH_VERSION))

/**
 * Node.js will refuse to load modules that weren't compiled against its own
 * module ABI number, exposed as the process.versions.modules property.
 *
 * When this version number is changed, node.js will refuse
 * to load older modules.  This should be done whenever
 * an API is broken in the C++ side, including in v8 or
 * other dependencies.
 */
#define NODE_MODULE_VERSION 48 /* Node.js v6.0.0 */

#endif  // SRC_NODE_VERSION_H_
