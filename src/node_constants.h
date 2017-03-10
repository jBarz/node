#ifndef SRC_NODE_CONSTANTS_H_
#define SRC_NODE_CONSTANTS_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"
#include "v8.h"

#if HAVE_OPENSSL
#define DEFAULT_CIPHER_LIST_CORE u8"ECDHE-RSA-AES128-GCM-SHA256:"     \
                                 u8"ECDHE-ECDSA-AES128-GCM-SHA256:"   \
                                 u8"ECDHE-RSA-AES256-GCM-SHA384:"     \
                                 u8"ECDHE-ECDSA-AES256-GCM-SHA384:"   \
                                 u8"DHE-RSA-AES128-GCM-SHA256:"       \
                                 u8"ECDHE-RSA-AES128-SHA256:"         \
                                 u8"DHE-RSA-AES128-SHA256:"           \
                                 u8"ECDHE-RSA-AES256-SHA384:"         \
                                 u8"DHE-RSA-AES256-SHA384:"           \
                                 u8"ECDHE-RSA-AES256-SHA256:"         \
                                 u8"DHE-RSA-AES256-SHA256:"           \
                                 u8"HIGH:"                            \
                                 u8"!aNULL:"                          \
                                 u8"!eNULL:"                          \
                                 u8"!EXPORT:"                         \
                                 u8"!DES:"                            \
                                 u8"!RC4:"                            \
                                 u8"!MD5:"                            \
                                 u8"!PSK:"                            \
                                 u8"!SRP:"                            \
                                 u8"!CAMELLIA"
#endif

namespace node {

#if HAVE_OPENSSL
extern const char* default_cipher_list;
#endif

void DefineConstants(v8::Isolate* isolate, v8::Local<v8::Object> target);
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_CONSTANTS_H_
