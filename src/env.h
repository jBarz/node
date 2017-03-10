#ifndef SRC_ENV_H_
#define SRC_ENV_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "ares.h"
#include "debug-agent.h"
#if HAVE_INSPECTOR
#include "inspector_agent.h"
#endif
#include "handle_wrap.h"
#include "req-wrap.h"
#include "tree.h"
#include "util.h"
#include "uv.h"
#include "v8.h"

#include <stdint.h>
#include <vector>

// Caveat emptor: we're going slightly crazy with macros here but the end
// hopefully justifies the means. We have a lot of per-context properties
// and adding and maintaining their getters and setters by hand would be
// a nightmare so let's make the preprocessor generate them for us.
//
// Make sure that any macros defined here are undefined again at the bottom
// of context-inl.h. The exceptions are NODE_CONTEXT_EMBEDDER_DATA_INDEX
// and NODE_ISOLATE_SLOT, they may have been defined externally.
namespace node {

// Pick an index that's hopefully out of the way when we're embedded inside
// another application. Performance-wise or memory-wise it doesn't matter:
// Context::SetAlignedPointerInEmbedderData() is backed by a FixedArray,
// worst case we pay a one-time penalty for resizing the array.
#ifndef NODE_CONTEXT_EMBEDDER_DATA_INDEX
#define NODE_CONTEXT_EMBEDDER_DATA_INDEX 32
#endif

// The slot 0 and 1 had already been taken by "gin" and "blink" in Chrome,
// and the size of isolate's slots is 4 by default, so using 3 should
// hopefully make node work independently when embedded into other
// application.
#ifndef NODE_ISOLATE_SLOT
#define NODE_ISOLATE_SLOT 3
#endif

// The number of items passed to push_values_to_array_function has diminishing
// returns around 8. This should be used at all call sites using said function.
#ifndef NODE_PUSH_VAL_TO_ARRAY_MAX
#define NODE_PUSH_VAL_TO_ARRAY_MAX 8
#endif

// Private symbols are per-isolate primitives but Environment proxies them
// for the sake of convenience.  Strings should be ASCII-only and have a
// "node:" prefix to avoid name clashes with third-party code.
#define PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES(V)                              \
  V(alpn_buffer_private_symbol, u8"node:alpnBuffer")                            \
  V(arrow_message_private_symbol, u8"node:arrowMessage")                        \
  V(contextify_context_private_symbol, u8"node:contextify:context")             \
  V(contextify_global_private_symbol, u8"node:contextify:global")               \
  V(decorated_private_symbol, u8"node:decorated")                               \
  V(npn_buffer_private_symbol, u8"node:npnBuffer")                              \
  V(processed_private_symbol, u8"node:processed")                               \
  V(selected_npn_buffer_private_symbol, u8"node:selectedNpnBuffer")             \

// Strings are per-isolate primitives but Environment proxies them
// for the sake of convenience.  Strings should be ASCII-only.
#define PER_ISOLATE_STRING_PROPERTIES(V)                                      \
  V(address_string, u8"address")                                                \
  V(args_string, u8"args")                                                      \
  V(async, u8"async")                                                           \
  V(async_queue_string, u8"_asyncQueue")                                        \
  V(buffer_string, u8"buffer")                                                  \
  V(bytes_string, u8"bytes")                                                    \
  V(bytes_parsed_string, u8"bytesParsed")                                       \
  V(bytes_read_string, u8"bytesRead")                                           \
  V(cached_data_string, u8"cachedData")                                         \
  V(cached_data_produced_string, u8"cachedDataProduced")                        \
  V(cached_data_rejected_string, u8"cachedDataRejected")                        \
  V(callback_string, u8"callback")                                              \
  V(change_string, u8"change")                                                  \
  V(oncertcb_string, u8"oncertcb")                                              \
  V(onclose_string, u8"_onclose")                                               \
  V(code_string, u8"code")                                                      \
  V(cwd_string, u8"cwd")                                                        \
  V(dest_string, u8"dest")                                                      \
  V(detached_string, u8"detached")                                              \
  V(disposed_string, u8"_disposed")                                             \
  V(domain_string, u8"domain")                                                  \
  V(emitting_top_level_domain_error_string, u8"_emittingTopLevelDomainError")   \
  V(exchange_string, u8"exchange")                                              \
  V(idle_string, u8"idle")                                                      \
  V(irq_string, u8"irq")                                                        \
  V(encoding_string, u8"encoding")                                              \
  V(enter_string, u8"enter")                                                    \
  V(env_pairs_string, u8"envPairs")                                             \
  V(env_string, u8"env")                                                        \
  V(errno_string, u8"errno")                                                    \
  V(error_string, u8"error")                                                    \
  V(events_string, u8"_events")                                                 \
  V(exiting_string, u8"_exiting")                                               \
  V(exit_code_string, u8"exitCode")                                             \
  V(exit_string, u8"exit")                                                      \
  V(expire_string, u8"expire")                                                  \
  V(exponent_string, u8"exponent")                                              \
  V(exports_string, u8"exports")                                                \
  V(ext_key_usage_string, u8"ext_key_usage")                                    \
  V(external_string, u8"external")                                              \
  V(external_stream_string, u8"_externalStream")                                \
  V(family_string, u8"family")                                                  \
  V(fatal_exception_string, u8"_fatalException")                                \
  V(fd_string, u8"fd")                                                          \
  V(file_string, u8"file")                                                      \
  V(fingerprint_string, u8"fingerprint")                                        \
  V(flags_string, u8"flags")                                                    \
  V(gid_string, u8"gid")                                                        \
  V(handle_string, u8"handle")                                                  \
  V(heap_total_string, u8"heapTotal")                                           \
  V(heap_used_string, u8"heapUsed")                                             \
  V(homedir_string, u8"homedir")                                                \
  V(hostmaster_string, u8"hostmaster")                                          \
  V(ignore_string, u8"ignore")                                                  \
  V(immediate_callback_string, u8"_immediateCallback")                          \
  V(infoaccess_string, u8"infoAccess")                                          \
  V(inherit_string, u8"inherit")                                                \
  V(input_string, u8"input")                                                    \
  V(internal_string, u8"internal")                                              \
  V(ipv4_string, u8"IPv4")                                                      \
  V(ipv6_string, u8"IPv6")                                                      \
  V(isalive_string, u8"isAlive")                                                \
  V(isclosing_string, u8"isClosing")                                            \
  V(issuer_string, u8"issuer")                                                  \
  V(issuercert_string, u8"issuerCertificate")                                   \
  V(kill_signal_string, u8"killSignal")                                         \
  V(mac_string, u8"mac")                                                        \
  V(max_buffer_string, u8"maxBuffer")                                           \
  V(message_string, u8"message")                                                \
  V(minttl_string, u8"minttl")                                                  \
  V(model_string, u8"model")                                                    \
  V(modulus_string, u8"modulus")                                                \
  V(name_string, u8"name")                                                      \
  V(netmask_string, u8"netmask")                                                \
  V(nice_string, u8"nice")                                                      \
  V(nsname_string, u8"nsname")                                                  \
  V(ocsp_request_string, u8"OCSPRequest")                                       \
  V(onchange_string, u8"onchange")                                              \
  V(onclienthello_string, u8"onclienthello")                                    \
  V(oncomplete_string, u8"oncomplete")                                          \
  V(onconnection_string, u8"onconnection")                                      \
  V(ondone_string, u8"ondone")                                                  \
  V(onerror_string, u8"onerror")                                                \
  V(onexit_string, u8"onexit")                                                  \
  V(onhandshakedone_string, u8"onhandshakedone")                                \
  V(onhandshakestart_string, u8"onhandshakestart")                              \
  V(onmessage_string, u8"onmessage")                                            \
  V(onnewsession_string, u8"onnewsession")                                      \
  V(onnewsessiondone_string, u8"onnewsessiondone")                              \
  V(onocspresponse_string, u8"onocspresponse")                                  \
  V(onread_string, u8"onread")                                                  \
  V(onreadstart_string, u8"onreadstart")                                        \
  V(onreadstop_string, u8"onreadstop")                                          \
  V(onselect_string, u8"onselect")                                              \
  V(onshutdown_string, u8"onshutdown")                                          \
  V(onsignal_string, u8"onsignal")                                              \
  V(onstop_string, u8"onstop")                                                  \
  V(onwrite_string, u8"onwrite")                                                \
  V(output_string, u8"output")                                                  \
  V(order_string, u8"order")                                                    \
  V(owner_string, u8"owner")                                                    \
  V(parse_error_string, u8"Parse Error")                                        \
  V(path_string, u8"path")                                                      \
  V(pbkdf2_error_string, u8"PBKDF2 Error")                                      \
  V(pid_string, u8"pid")                                                        \
  V(pipe_string, u8"pipe")                                                      \
  V(port_string, u8"port")                                                      \
  V(preference_string, u8"preference")                                          \
  V(priority_string, u8"priority")                                              \
  V(produce_cached_data_string, u8"produceCachedData")                          \
  V(raw_string, u8"raw")                                                        \
  V(readable_string, u8"readable")                                              \
  V(received_shutdown_string, u8"receivedShutdown")                             \
  V(refresh_string, u8"refresh")                                                \
  V(regexp_string, u8"regexp")                                                  \
  V(rename_string, u8"rename")                                                  \
  V(replacement_string, u8"replacement")                                        \
  V(retry_string, u8"retry")                                                    \
  V(rss_string, u8"rss")                                                        \
  V(serial_string, u8"serial")                                                  \
  V(scopeid_string, u8"scopeid")                                                \
  V(sent_shutdown_string, u8"sentShutdown")                                     \
  V(serial_number_string, u8"serialNumber")                                     \
  V(service_string, u8"service")                                                \
  V(servername_string, u8"servername")                                          \
  V(session_id_string, u8"sessionId")                                           \
  V(shell_string, u8"shell")                                                    \
  V(signal_string, u8"signal")                                                  \
  V(size_string, u8"size")                                                      \
  V(sni_context_err_string, u8"Invalid SNI context")                            \
  V(sni_context_string, u8"sni_context")                                        \
  V(speed_string, u8"speed")                                                    \
  V(stack_string, u8"stack")                                                    \
  V(status_string, u8"status")                                                  \
  V(stdio_string, u8"stdio")                                                    \
  V(subject_string, u8"subject")                                                \
  V(subjectaltname_string, u8"subjectaltname")                                  \
  V(sys_string, u8"sys")                                                        \
  V(syscall_string, u8"syscall")                                                \
  V(tick_callback_string, u8"_tickCallback")                                    \
  V(tick_domain_cb_string, u8"_tickDomainCallback")                             \
  V(ticketkeycallback_string, u8"onticketkeycallback")                          \
  V(timeout_string, u8"timeout")                                                \
  V(times_string, u8"times")                                                    \
  V(tls_ticket_string, u8"tlsTicket")                                           \
  V(type_string, u8"type")                                                      \
  V(uid_string, u8"uid")                                                        \
  V(unknown_string, u8"<unknown>")                                              \
  V(user_string, u8"user")                                                      \
  V(username_string, u8"username")                                              \
  V(valid_from_string, u8"valid_from")                                          \
  V(valid_to_string, u8"valid_to")                                              \
  V(verify_error_string, u8"verifyError")                                       \
  V(version_string, u8"version")                                                \
  V(weight_string, u8"weight")                                                  \
  V(windows_verbatim_arguments_string, u8"windowsVerbatimArguments")            \
  V(wrap_string, u8"wrap")                                                      \
  V(writable_string, u8"writable")                                              \
  V(write_queue_size_string, u8"writeQueueSize")                                \
  V(x_forwarded_string, u8"x-forwarded-for")                                    \
  V(zero_return_string, u8"ZERO_RETURN")                                        \

#define ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)                           \
  V(as_external, v8::External)                                                \
  V(async_hooks_destroy_function, v8::Function)                               \
  V(async_hooks_init_function, v8::Function)                                  \
  V(async_hooks_post_function, v8::Function)                                  \
  V(async_hooks_pre_function, v8::Function)                                   \
  V(binding_cache_object, v8::Object)                                         \
  V(buffer_constructor_function, v8::Function)                                \
  V(buffer_prototype_object, v8::Object)                                      \
  V(context, v8::Context)                                                     \
  V(domain_array, v8::Array)                                                  \
  V(domains_stack_array, v8::Array)                                           \
  V(fs_stats_constructor_function, v8::Function)                              \
  V(generic_internal_field_template, v8::ObjectTemplate)                      \
  V(jsstream_constructor_template, v8::FunctionTemplate)                      \
  V(module_load_list_array, v8::Array)                                        \
  V(pipe_constructor_template, v8::FunctionTemplate)                          \
  V(process_object, v8::Object)                                               \
  V(promise_reject_function, v8::Function)                                    \
  V(push_values_to_array_function, v8::Function)                              \
  V(script_context_constructor_template, v8::FunctionTemplate)                \
  V(script_data_constructor_function, v8::Function)                           \
  V(secure_context_constructor_template, v8::FunctionTemplate)                \
  V(tcp_constructor_template, v8::FunctionTemplate)                           \
  V(tick_callback_function, v8::Function)                                     \
  V(tls_wrap_constructor_function, v8::Function)                              \
  V(tls_wrap_constructor_template, v8::FunctionTemplate)                      \
  V(tty_constructor_template, v8::FunctionTemplate)                           \
  V(udp_constructor_function, v8::Function)                                   \
  V(write_wrap_constructor_function, v8::Function)                            \

class Environment;

struct node_ares_task {
  Environment* env;
  ares_socket_t sock;
  uv_poll_t poll_watcher;
  RB_ENTRY(node_ares_task) node;
};

RB_HEAD(node_ares_task_list, node_ares_task);

class Environment {
 public:
  class AsyncHooks {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline bool callbacks_enabled();
    inline void set_enable_callbacks(uint32_t flag);

   private:
    friend class Environment;  // So we can call the constructor.
    inline AsyncHooks();

    enum Fields {
      // Set this to not zero if the init hook should be called.
      kEnableCallbacks,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(AsyncHooks);
  };

  class AsyncCallbackScope {
   public:
    explicit AsyncCallbackScope(Environment* env);
    ~AsyncCallbackScope();

    inline bool in_makecallback();

   private:
    Environment* env_;

    DISALLOW_COPY_AND_ASSIGN(AsyncCallbackScope);
  };

  class DomainFlag {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline uint32_t count() const;

   private:
    friend class Environment;  // So we can call the constructor.
    inline DomainFlag();

    enum Fields {
      kCount,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(DomainFlag);
  };

  class TickInfo {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline uint32_t index() const;
    inline uint32_t length() const;
    inline void set_index(uint32_t value);

   private:
    friend class Environment;  // So we can call the constructor.
    inline TickInfo();

    enum Fields {
      kIndex,
      kLength,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(TickInfo);
  };

  class ArrayBufferAllocatorInfo {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline bool no_zero_fill() const;
    inline void reset_fill_flag();

   private:
    friend class Environment;  // So we can call the constructor.
    inline ArrayBufferAllocatorInfo();

    enum Fields {
      kNoZeroFill,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(ArrayBufferAllocatorInfo);
  };

  typedef void (*HandleCleanupCb)(Environment* env,
                                  uv_handle_t* handle,
                                  void* arg);

  class HandleCleanup {
   private:
    friend class Environment;

    HandleCleanup(uv_handle_t* handle, HandleCleanupCb cb, void* arg)
        : handle_(handle),
          cb_(cb),
          arg_(arg) {
    }

    uv_handle_t* handle_;
    HandleCleanupCb cb_;
    void* arg_;
    ListNode<HandleCleanup> handle_cleanup_queue_;
  };

  static inline Environment* GetCurrent(v8::Isolate* isolate);
  static inline Environment* GetCurrent(v8::Local<v8::Context> context);
  static inline Environment* GetCurrent(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  template <typename T>
  static inline Environment* GetCurrent(
      const v8::PropertyCallbackInfo<T>& info);

  // See CreateEnvironment() in src/node.cc.
  static inline Environment* New(v8::Local<v8::Context> context,
                                 uv_loop_t* loop);
  inline void CleanupHandles();
  inline void Dispose();

  void AssignToContext(v8::Local<v8::Context> context);

  inline v8::Isolate* isolate() const;
  inline uv_loop_t* event_loop() const;
  inline bool async_wrap_callbacks_enabled() const;
  inline bool in_domain() const;
  inline uint32_t watched_providers() const;

  static inline Environment* from_immediate_check_handle(uv_check_t* handle);
  static inline Environment* from_destroy_ids_idle_handle(uv_idle_t* handle);
  inline uv_check_t* immediate_check_handle();
  inline uv_idle_t* immediate_idle_handle();
  inline uv_idle_t* destroy_ids_idle_handle();

  static inline Environment* from_idle_prepare_handle(uv_prepare_t* handle);
  inline uv_prepare_t* idle_prepare_handle();

  static inline Environment* from_idle_check_handle(uv_check_t* handle);
  inline uv_check_t* idle_check_handle();

  // Register clean-up cb to be called on env->Dispose()
  inline void RegisterHandleCleanup(uv_handle_t* handle,
                                    HandleCleanupCb cb,
                                    void *arg);
  inline void FinishHandleCleanup(uv_handle_t* handle);

  inline AsyncHooks* async_hooks();
  inline DomainFlag* domain_flag();
  inline TickInfo* tick_info();
  inline ArrayBufferAllocatorInfo* array_buffer_allocator_info();
  inline uint64_t timer_base() const;

  static inline Environment* from_cares_timer_handle(uv_timer_t* handle);
  inline uv_timer_t* cares_timer_handle();
  inline ares_channel cares_channel();
  inline ares_channel* cares_channel_ptr();
  inline node_ares_task_list* cares_task_list();

  inline bool using_domains() const;
  inline void set_using_domains(bool value);

  inline bool printed_error() const;
  inline void set_printed_error(bool value);

  void PrintSyncTrace() const;
  inline void set_trace_sync_io(bool value);

  inline int64_t get_async_wrap_uid();

  // List of id's that have been destroyed and need the destroy() cb called.
  inline std::vector<int64_t>* destroy_ids_list();

  inline uint32_t* heap_statistics_buffer() const;
  inline void set_heap_statistics_buffer(uint32_t* pointer);

  inline uint32_t* heap_space_statistics_buffer() const;
  inline void set_heap_space_statistics_buffer(uint32_t* pointer);

  inline char* http_parser_buffer() const;
  inline void set_http_parser_buffer(char* buffer);

  inline void ThrowError(const char* errmsg);
  inline void ThrowTypeError(const char* errmsg);
  inline void ThrowRangeError(const char* errmsg);
  inline void ThrowErrnoException(int errorno,
                                  const char* syscall = nullptr,
                                  const char* message = nullptr,
                                  const char* path = nullptr);
  inline void ThrowUVException(int errorno,
                               const char* syscall = nullptr,
                               const char* message = nullptr,
                               const char* path = nullptr,
                               const char* dest = nullptr);

  inline v8::Local<v8::FunctionTemplate>
      NewFunctionTemplate(v8::FunctionCallback callback,
                          v8::Local<v8::Signature> signature =
                              v8::Local<v8::Signature>());

  // Convenience methods for NewFunctionTemplate().
  inline void SetMethod(v8::Local<v8::Object> that,
                        const char* name,
                        v8::FunctionCallback callback);
  inline void SetProtoMethod(v8::Local<v8::FunctionTemplate> that,
                             const char* name,
                             v8::FunctionCallback callback);
  inline void SetTemplateMethod(v8::Local<v8::FunctionTemplate> that,
                                const char* name,
                                v8::FunctionCallback callback);

  inline v8::Local<v8::Object> NewInternalFieldObject();

  // Strings and private symbols are shared across shared contexts
  // The getters simply proxy to the per-isolate primitive.
#define VP(PropertyName, StringValue) V(v8::Private, PropertyName, StringValue)
#define VS(PropertyName, StringValue) V(v8::String, PropertyName, StringValue)
#define V(TypeName, PropertyName, StringValue)                                \
  inline v8::Local<TypeName> PropertyName() const;
  PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES(VP)
  PER_ISOLATE_STRING_PROPERTIES(VS)
#undef V
#undef VS
#undef VP

#define V(PropertyName, TypeName)                                             \
  inline v8::Local<TypeName> PropertyName() const;                            \
  inline void set_ ## PropertyName(v8::Local<TypeName> value);
  ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)
#undef V

  inline debugger::Agent* debugger_agent() {
    return &debugger_agent_;
  }

#if HAVE_INSPECTOR
  inline inspector::Agent* inspector_agent() {
    return &inspector_agent_;
  }
#endif

  typedef ListHead<HandleWrap, &HandleWrap::handle_wrap_queue_> HandleWrapQueue;
  typedef ListHead<ReqWrap<uv_req_t>, &ReqWrap<uv_req_t>::req_wrap_queue_>
          ReqWrapQueue;

  inline HandleWrapQueue* handle_wrap_queue() { return &handle_wrap_queue_; }
  inline ReqWrapQueue* req_wrap_queue() { return &req_wrap_queue_; }

  static const int kContextEmbedderDataIndex = NODE_CONTEXT_EMBEDDER_DATA_INDEX;

 private:
  inline void ThrowError(v8::Local<v8::Value> (*fun)(v8::Local<v8::String>),
                         const char* errmsg);

  static const int kIsolateSlot = NODE_ISOLATE_SLOT;

  class IsolateData;
  inline Environment(v8::Local<v8::Context> context, uv_loop_t* loop);
  inline ~Environment();
  inline IsolateData* isolate_data() const;

  v8::Isolate* const isolate_;
  IsolateData* const isolate_data_;
  uv_check_t immediate_check_handle_;
  uv_idle_t immediate_idle_handle_;
  uv_idle_t destroy_ids_idle_handle_;
  uv_prepare_t idle_prepare_handle_;
  uv_check_t idle_check_handle_;
  AsyncHooks async_hooks_;
  DomainFlag domain_flag_;
  TickInfo tick_info_;
  ArrayBufferAllocatorInfo array_buffer_allocator_info_;
  const uint64_t timer_base_;
  uv_timer_t cares_timer_handle_;
  ares_channel cares_channel_;
  node_ares_task_list cares_task_list_;
  bool using_domains_;
  bool printed_error_;
  bool trace_sync_io_;
  size_t makecallback_cntr_;
  int64_t async_wrap_uid_;
  std::vector<int64_t> destroy_ids_list_;
  debugger::Agent debugger_agent_;
#if HAVE_INSPECTOR
  inspector::Agent inspector_agent_;
#endif

  HandleWrapQueue handle_wrap_queue_;
  ReqWrapQueue req_wrap_queue_;
  ListHead<HandleCleanup,
           &HandleCleanup::handle_cleanup_queue_> handle_cleanup_queue_;
  int handle_cleanup_waiting_;

  uint32_t* heap_statistics_buffer_ = nullptr;
  uint32_t* heap_space_statistics_buffer_ = nullptr;

  char* http_parser_buffer_;

#define V(PropertyName, TypeName)                                             \
  v8::Persistent<TypeName> PropertyName ## _;
  ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)
#undef V

  // Per-thread, reference-counted singleton.
  class IsolateData {
   public:
    static inline IsolateData* GetOrCreate(v8::Isolate* isolate,
                                           uv_loop_t* loop);
    inline void Put();
    inline uv_loop_t* event_loop() const;

#define VP(PropertyName, StringValue) V(v8::Private, PropertyName, StringValue)
#define VS(PropertyName, StringValue) V(v8::String, PropertyName, StringValue)
#define V(TypeName, PropertyName, StringValue)                                \
    inline v8::Local<TypeName> PropertyName() const;
    PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES(VP)
    PER_ISOLATE_STRING_PROPERTIES(VS)
#undef V
#undef VS
#undef VP

   private:
    inline static IsolateData* Get(v8::Isolate* isolate);
    inline explicit IsolateData(v8::Isolate* isolate, uv_loop_t* loop);
    inline v8::Isolate* isolate() const;

    uv_loop_t* const event_loop_;
    v8::Isolate* const isolate_;

#define VP(PropertyName, StringValue) V(v8::Private, PropertyName, StringValue)
#define VS(PropertyName, StringValue) V(v8::String, PropertyName, StringValue)
#define V(TypeName, PropertyName, StringValue)                                \
    v8::Eternal<TypeName> PropertyName ## _;
    PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES(VP)
    PER_ISOLATE_STRING_PROPERTIES(VS)
#undef V
#undef VS
#undef VP

    unsigned int ref_count_;

    DISALLOW_COPY_AND_ASSIGN(IsolateData);
  };

  DISALLOW_COPY_AND_ASSIGN(Environment);
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_ENV_H_
