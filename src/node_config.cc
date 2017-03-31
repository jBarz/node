#include "node.h"
#include "node_i18n.h"
#include "env.h"
#include "env-inl.h"
#include "util.h"
#include "util-inl.h"


namespace node {

using v8::Context;
using v8::Local;
using v8::Object;
using v8::ReadOnly;
using v8::Value;

// The config binding is used to provide an internal view of compile or runtime
// config options that are required internally by lib/*.js code. This is an
// alternative to dropping additional properties onto the process object as
// has been the practice previously in node.cc.

#define READONLY_BOOLEAN_PROPERTY(str)                                        \
  do {                                                                        \
    target->DefineOwnProperty(env->context(),                                 \
                              OneByteString(env->isolate(), str),             \
                              True(env->isolate()), ReadOnly).FromJust();     \
  } while (0)

void InitConfig(Local<Object> target,
                Local<Value> unused,
                Local<Context> context) {
  Environment* env = Environment::GetCurrent(context);
#ifdef NODE_HAVE_I18N_SUPPORT

  READONLY_BOOLEAN_PROPERTY("\x68\x61\x73\x49\x6e\x74\x6c");

#ifdef NODE_HAVE_SMALL_ICU
  READONLY_BOOLEAN_PROPERTY("\x68\x61\x73\x53\x6d\x61\x6c\x6c\x49\x43\x55");
#endif  // NODE_HAVE_SMALL_ICU

  if (flag_icu_data_dir)
    READONLY_BOOLEAN_PROPERTY("\x75\x73\x69\x6e\x67\x49\x43\x55\x44\x61\x74\x61\x44\x69\x72");
#endif  // NODE_HAVE_I18N_SUPPORT

  if (config_preserve_symlinks)
    READONLY_BOOLEAN_PROPERTY("\x70\x72\x65\x73\x65\x72\x76\x65\x53\x79\x6d\x6c\x69\x6e\x6b\x73");
}  // InitConfig

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(config, node::InitConfig)
