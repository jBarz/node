#include "env.h"
#include "env-inl.h"
#include "v8.h"

#if defined(_MSC_VER)
#define getpid GetCurrentProcessId
#else
#include <unistd.h>
#endif

#include <stdio.h>

namespace node {

using v8::HandleScope;
using v8::Local;
using v8::Message;
using v8::StackFrame;
using v8::StackTrace;

void Environment::PrintSyncTrace() const {
  if (!trace_sync_io_)
    return;

  HandleScope handle_scope(isolate());
  Local<v8::StackTrace> stack =
      StackTrace::CurrentStackTrace(isolate(), 10, StackTrace::kDetailed);

  fprintf(stderr, "(node:%d) WARNING: Detected use of sync API\n", getpid());

  for (int i = 0; i < stack->GetFrameCount() - 1; i++) {
    Local<StackFrame> stack_frame = stack->GetFrame(i);
    node::Utf8Value fn_name_s(isolate(), stack_frame->GetFunctionName());
    node::Utf8Value script_name(isolate(), stack_frame->GetScriptName());
    const int line_number = stack_frame->GetLineNumber();
    const int column = stack_frame->GetColumn();

    if (stack_frame->IsEval()) {
      if (stack_frame->GetScriptId() == Message::kNoScriptIdInfo) {
        fprintf(stderr, "    at [eval]:%i:%i\n", line_number, column);
      } else {
        fprintf(stderr,
                "\x20\x20\x20\x20\x61\x74\x20\x5b\x65\x76\x61\x6c\x5d\x20\x28\x6c\xa2\x3a\x6c\x89\x3a\x6c\x89\x29\xa",
                *script_name,
                line_number,
                column);
      }
      break;
    }

    if (fn_name_s.length() == 0) {
      fprintf(stderr, "    at %s:%i:%i\n", *script_name, line_number, column);
    } else {
      fprintf(stderr,
              "\x20\x20\x20\x20\x61\x74\x20\x6c\xa2\x20\x28\x6c\xa2\x3a\x6c\x89\x3a\x6c\x89\x29\xa",
              *fn_name_s,
              *script_name,
              line_number,
              column);
    }
  }
  fflush(stderr);
}

}  // namespace node
