//! C-ABI surface for the Go (CGO) host.
//!
//! Every function in this module is `extern "C"` and wrapped in
//! [`std::panic::catch_unwind`] to prevent Rust panics from crossing the
//! FFI boundary (which is UB).
//!
//! The Go side interacts with genesis-core exclusively through opaque
//! [`GenesisHandle`] pointers and the functions declared here.  State is
//! tracked both in the Rust typestate machine (compile time) and in the
//! [`StateTag`] field of the handle (runtime, for the Go host).
//!
//! Data returns (PublicArtifacts, VerifyResult, GenesisStatus) are
//! serialised as JSON into the `data_json` field of [`GenesisResult`].
//! The Go host should check `data_json` for non-null and parse the JSON.

use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::panic;
use std::ptr;

use crate::audit::{AuditSink, FfiAuditSink, NullAuditSink};
use crate::k8s::MockSecretInjector;
use crate::kms::config::{create_provider, KmsConfig};
use crate::state::{
    Active, Degraded, Genesis, GenesisConfig, Initialized, Rotating, StateTag, Uninitialized,
};

// ── Callback types ───────────────────────────────────────────────────

/// C-compatible audit callback signature.
///
/// The callee receives a pointer to UTF-8 JSON and its byte length.
/// Data must be copied if it needs to outlive the call.
/// Pass a null function pointer for no-op audit.
pub type AuditCallback = Option<unsafe extern "C" fn(data: *const u8, len: usize)>;

// ── FFI-visible types ────────────────────────────────────────────────

/// Opaque handle that the Go host uses to refer to a genesis-core
/// state machine instance.
///
/// The `ptr` field points to a heap-allocated [`GenesisInner`] enum.
/// The `state` field mirrors the current typestate for runtime dispatch.
#[repr(C)]
pub struct GenesisHandle {
    pub ptr: *mut c_void,
    pub state: StateTag,
}

/// Result type returned by every FFI function.
///
/// On success: `success == true`, `handle` is valid, `error_code == 0`.
/// On failure: `success == false`, `error_code` is non-zero,
///             `error_message` is a NUL-terminated UTF-8 string (caller
///             must free with `genesis_free_string`).
///
/// `data_json` carries serialised JSON for functions that return extra
/// data (PublicArtifacts, VerifyResult, GenesisStatus).  NULL when no
/// data is returned.  Caller must free with `genesis_free_string`.
#[repr(C)]
pub struct GenesisResult {
    pub success: bool,
    pub error_code: u32,
    pub error_message: *mut c_char,
    pub handle: GenesisHandle,
    pub data_json: *mut c_char,
}

// ── GenesisInner ─────────────────────────────────────────────────────

/// Type-erased wrapper around all possible typed states of the genesis
/// state machine.
///
/// Used inside the heap allocation behind [`GenesisHandle::ptr`] so that
/// the Go host can hold a single opaque pointer regardless of the
/// current state.
pub enum GenesisInner {
    Uninitialized(Genesis<Uninitialized>),
    Initialized(Genesis<Initialized>),
    Bootstrapping(crate::state::GenesisBootstrapping),
    Active(Genesis<Active>),
    Rotating(Genesis<Rotating>),
    Degraded(Genesis<Degraded>),
}

impl GenesisInner {
    /// Return the runtime state tag for this variant.
    fn state_tag(&self) -> StateTag {
        match self {
            GenesisInner::Uninitialized(_) => StateTag::Uninitialized,
            GenesisInner::Initialized(_) => StateTag::Initialized,
            GenesisInner::Bootstrapping(_) => StateTag::Bootstrapping,
            GenesisInner::Active(_) => StateTag::Active,
            GenesisInner::Rotating(_) => StateTag::Rotating,
            GenesisInner::Degraded(_) => StateTag::Degraded,
        }
    }
}

// ── Helper functions ─────────────────────────────────────────────────

/// Allocate a `GenesisInner` on the heap and return an opaque handle.
fn inner_to_handle(inner: GenesisInner) -> GenesisHandle {
    let tag = inner.state_tag();
    let boxed = Box::new(inner);
    GenesisHandle {
        ptr: Box::into_raw(boxed) as *mut c_void,
        state: tag,
    }
}

/// Create an error result with the given code and message.
///
/// **Warning:** This returns a null handle.  Only use this for errors
/// that happen *before* `take_inner` has consumed the caller's handle.
/// After `take_inner`, use [`error_with_handle`] instead so the Go host
/// can recover the (re-boxed) state.
fn error_result(code: u32, message: &str) -> GenesisResult {
    let c_msg =
        CString::new(message).unwrap_or_else(|_| CString::new("(invalid error message)").unwrap());
    GenesisResult {
        success: false,
        error_code: code,
        error_message: c_msg.into_raw(),
        handle: GenesisHandle {
            ptr: ptr::null_mut(),
            state: StateTag::Uninitialized,
        },
        data_json: ptr::null_mut(),
    }
}

/// Create an error result that **preserves the handle**.
///
/// Use this for every error path that fires *after* `take_inner` has
/// consumed the caller's handle.  The handle is returned inside the
/// result so the Go host can store it back and later call `genesis_free`.
fn error_with_handle(code: u32, message: &str, handle: GenesisHandle) -> GenesisResult {
    let c_msg =
        CString::new(message).unwrap_or_else(|_| CString::new("(invalid error message)").unwrap());
    GenesisResult {
        success: false,
        error_code: code,
        error_message: c_msg.into_raw(),
        handle,
        data_json: ptr::null_mut(),
    }
}

/// Graft a valid handle onto a null-handle error result.
///
/// This is used when a helper (e.g. `parse_c_str`, `parse_kms_config`)
/// returns an `Err(GenesisResult)` with a null handle, but we have
/// already consumed the caller's handle via `take_inner` and need to
/// return a recoverable error.
fn graft_handle(mut err: GenesisResult, handle: GenesisHandle) -> GenesisResult {
    err.handle = handle;
    err
}

/// Create a success result with the given handle and no data.
fn success_result(handle: GenesisHandle) -> GenesisResult {
    GenesisResult {
        success: true,
        error_code: 0,
        error_message: ptr::null_mut(),
        handle,
        data_json: ptr::null_mut(),
    }
}

/// Create a success result with the given handle and JSON data.
fn success_result_with_data(handle: GenesisHandle, json: &str) -> GenesisResult {
    let c_json = CString::new(json).unwrap_or_else(|_| CString::new("{}").unwrap());
    GenesisResult {
        success: true,
        error_code: 0,
        error_message: ptr::null_mut(),
        handle,
        data_json: c_json.into_raw(),
    }
}

/// Create a panic result (code 999).
fn panic_result() -> GenesisResult {
    error_result(999, "Rust panic caught at FFI boundary")
}

/// Parse a C string pointer into a Rust `&str`.
///
/// # Safety
///
/// `ptr` must be a valid NUL-terminated C string.
unsafe fn parse_c_str<'a>(ptr: *const c_char) -> Result<&'a str, GenesisResult> {
    if ptr.is_null() {
        return Err(error_result(1, "null string pointer"));
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|e| error_result(1, &format!("invalid UTF-8: {e}")))
}

/// Parse a KMS config JSON string into a [`KmsConfig`].
unsafe fn parse_kms_config(kms_config_json: *const c_char) -> Result<KmsConfig, GenesisResult> {
    let json_str = parse_c_str(kms_config_json)?;
    serde_json::from_str::<KmsConfig>(json_str)
        .map_err(|e| error_result(500, &format!("invalid KMS config JSON: {e}")))
}

/// Reconstruct a `GenesisInner` from a handle, consuming the handle.
///
/// # Safety
///
/// The handle pointer must have been created by `inner_to_handle` and
/// must not have been freed.
unsafe fn take_inner(handle: GenesisHandle) -> Result<GenesisInner, GenesisResult> {
    if handle.ptr.is_null() {
        return Err(error_result(1, "null handle pointer"));
    }
    Ok(*Box::from_raw(handle.ptr as *mut GenesisInner))
}

// ── FFI entry points ─────────────────────────────────────────────────

/// Create a new genesis-core instance in the `Uninitialized` state.
///
/// `config_json` is a NUL-terminated UTF-8 JSON string that deserialises
/// to a [`GenesisConfig`].  `audit_cb` is an optional audit callback; pass
/// NULL for a no-op sink.
///
/// # Safety
///
/// `config_json` must be a valid NUL-terminated C string or NULL.
#[no_mangle]
pub unsafe extern "C" fn genesis_new(
    config_json: *const c_char,
    audit_cb: AuditCallback,
) -> GenesisResult {
    panic::catch_unwind(|| {
        let config_str = match parse_c_str(config_json) {
            Ok(s) => s,
            Err(r) => return r,
        };

        let config: GenesisConfig = match serde_json::from_str(config_str) {
            Ok(c) => c,
            Err(e) => return error_result(500, &format!("invalid config JSON: {e}")),
        };

        let audit: Box<dyn AuditSink> = match audit_cb {
            Some(cb) => Box::new(FfiAuditSink::new(cb)),
            None => Box::new(NullAuditSink),
        };

        let genesis = Genesis::<Uninitialized>::new(config, audit);
        let inner = GenesisInner::Uninitialized(genesis);
        success_result(inner_to_handle(inner))
    })
    .unwrap_or_else(|_| panic_result())
}

/// Generate a keypair, KMS-encrypt the private key, and transition to
/// `Initialized`.
///
/// On success, `data_json` contains JSON-serialised [`PublicArtifacts`].
///
/// # Safety
///
/// `handle` must be a valid `GenesisHandle` in the `Uninitialized` state.
/// `kms_config_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn genesis_init(
    handle: GenesisHandle,
    kms_config_json: *const c_char,
) -> GenesisResult {
    panic::catch_unwind(|| {
        let inner = match take_inner(handle) {
            Ok(i) => i,
            Err(r) => return r,
        };

        let genesis = match inner {
            GenesisInner::Uninitialized(g) => g,
            other => {
                let handle = inner_to_handle(other);
                return error_with_handle(
                    102,
                    "invalid state: genesis_init requires Uninitialized state",
                    handle,
                );
            }
        };

        let kms_config = match parse_kms_config(kms_config_json) {
            Ok(c) => c,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Uninitialized(genesis));
                return graft_handle(r, handle);
            }
        };

        let provider = match create_provider(&kms_config) {
            Ok(p) => p,
            Err(e) => {
                let handle = inner_to_handle(GenesisInner::Uninitialized(genesis));
                return error_with_handle(e.error_code(), &e.to_string(), handle);
            }
        };

        match genesis.init(&*provider) {
            Ok((initialized, artifacts)) => {
                let new_inner = GenesisInner::Initialized(initialized);
                let json = match serde_json::to_string(&artifacts) {
                    Ok(j) => j,
                    Err(e) => {
                        // Serialization failed but we have the new state --
                        // return it so the Go host doesn't lose the handle.
                        let handle = inner_to_handle(new_inner);
                        return error_with_handle(
                            500,
                            &format!("failed to serialize artifacts: {e}"),
                            handle,
                        );
                    }
                };
                success_result_with_data(inner_to_handle(new_inner), &json)
            }
            // init() consumes genesis -- no state to return.
            Err(e) => error_result(e.error_code(), &e.to_string()),
        }
    })
    .unwrap_or_else(|_| panic_result())
}

/// Load a previously-persisted keypair and transition to `Initialized`.
///
/// # Safety
///
/// `handle` must be a valid `GenesisHandle` in the `Uninitialized` state.
/// `public_key` must be a valid NUL-terminated C string.
/// `envelope_ciphertext` + `envelope_len` must point to a valid byte buffer.
#[no_mangle]
pub unsafe extern "C" fn genesis_load(
    handle: GenesisHandle,
    public_key: *const c_char,
    envelope_ciphertext: *const u8,
    envelope_len: usize,
) -> GenesisResult {
    panic::catch_unwind(|| {
        let inner = match take_inner(handle) {
            Ok(i) => i,
            Err(r) => return r,
        };

        let genesis = match inner {
            GenesisInner::Uninitialized(g) => g,
            other => {
                let handle = inner_to_handle(other);
                return error_with_handle(
                    102,
                    "invalid state: genesis_load requires Uninitialized state",
                    handle,
                );
            }
        };

        let pk_str = match parse_c_str(public_key) {
            Ok(s) => s.to_string(),
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Uninitialized(genesis));
                return graft_handle(r, handle);
            }
        };

        if envelope_ciphertext.is_null() || envelope_len == 0 {
            let handle = inner_to_handle(GenesisInner::Uninitialized(genesis));
            return error_with_handle(100, "envelope_ciphertext is null or empty", handle);
        }
        let envelope = std::slice::from_raw_parts(envelope_ciphertext, envelope_len).to_vec();

        let initialized = genesis.load(pk_str, envelope);
        let new_inner = GenesisInner::Initialized(initialized);
        success_result(inner_to_handle(new_inner))
    })
    .unwrap_or_else(|_| panic_result())
}

/// Verify the stored envelope by decrypting and re-deriving the public key.
///
/// On success, writes a JSON-serialised [`VerifyResult`] to `*result_json_out`
/// (caller must free with `genesis_free_string`).
///
/// # Safety
///
/// `handle` must be a valid `GenesisHandle` in the `Initialized` state.
/// `kms_config_json` must be a valid NUL-terminated C string.
/// `result_json_out` must point to a valid `*mut c_char` to receive the
/// result JSON (caller must free with `genesis_free_string`).
#[no_mangle]
pub unsafe extern "C" fn genesis_verify(
    handle: GenesisHandle,
    kms_config_json: *const c_char,
    result_json_out: *mut *mut c_char,
) -> GenesisResult {
    panic::catch_unwind(|| {
        let inner = match take_inner(handle) {
            Ok(i) => i,
            Err(r) => return r,
        };

        let genesis = match inner {
            GenesisInner::Initialized(g) => g,
            other => {
                let handle = inner_to_handle(other);
                return error_with_handle(
                    102,
                    "invalid state: genesis_verify requires Initialized state",
                    handle,
                );
            }
        };

        let kms_config = match parse_kms_config(kms_config_json) {
            Ok(c) => c,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Initialized(genesis));
                return graft_handle(r, handle);
            }
        };

        let provider = match create_provider(&kms_config) {
            Ok(p) => p,
            Err(e) => {
                let handle = inner_to_handle(GenesisInner::Initialized(genesis));
                return error_with_handle(e.error_code(), &e.to_string(), handle);
            }
        };

        match genesis.verify(&*provider) {
            Ok(verify_result) => {
                // Write JSON to the out-parameter if provided.
                if !result_json_out.is_null() {
                    match serde_json::to_string(&verify_result) {
                        Ok(json) => {
                            let c_json =
                                CString::new(json).unwrap_or_else(|_| CString::new("{}").unwrap());
                            *result_json_out = c_json.into_raw();
                        }
                        Err(_) => {
                            *result_json_out = ptr::null_mut();
                        }
                    }
                }
                // verify is non-consuming -- genesis stays Initialized.
                let new_inner = GenesisInner::Initialized(genesis);
                let json = serde_json::to_string(&verify_result).unwrap_or_default();
                success_result_with_data(inner_to_handle(new_inner), &json)
            }
            Err(e) => {
                // verify is non-consuming via borrow, but we consumed the
                // inner above. Put it back.
                let handle = inner_to_handle(GenesisInner::Initialized(genesis));
                error_with_handle(e.error_code(), &e.to_string(), handle)
            }
        }
    })
    .unwrap_or_else(|_| panic_result())
}

/// Decrypt the envelope and transition to `Bootstrapping`.
///
/// # Safety
///
/// `handle` must be a valid `GenesisHandle` in the `Initialized` state.
/// `kms_config_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn genesis_begin_bootstrap(
    handle: GenesisHandle,
    kms_config_json: *const c_char,
) -> GenesisResult {
    panic::catch_unwind(|| {
        let inner = match take_inner(handle) {
            Ok(i) => i,
            Err(r) => return r,
        };

        let genesis = match inner {
            GenesisInner::Initialized(g) => g,
            other => {
                let handle = inner_to_handle(other);
                return error_with_handle(
                    102,
                    "invalid state: genesis_begin_bootstrap requires Initialized state",
                    handle,
                );
            }
        };

        let kms_config = match parse_kms_config(kms_config_json) {
            Ok(c) => c,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Initialized(genesis));
                return graft_handle(r, handle);
            }
        };

        let provider = match create_provider(&kms_config) {
            Ok(p) => p,
            Err(e) => {
                let handle = inner_to_handle(GenesisInner::Initialized(genesis));
                return error_with_handle(e.error_code(), &e.to_string(), handle);
            }
        };

        match genesis.begin_bootstrap(&*provider) {
            Ok(bootstrapping) => {
                let new_inner = GenesisInner::Bootstrapping(bootstrapping);
                success_result(inner_to_handle(new_inner))
            }
            // begin_bootstrap() consumes genesis -- no state to return.
            Err(e) => error_result(e.error_code(), &e.to_string()),
        }
    })
    .unwrap_or_else(|_| panic_result())
}

/// Inject the decrypted key material into a Kubernetes secret and
/// transition to `Active`.
///
/// # Safety
///
/// `handle` must be a valid `GenesisHandle` in the `Bootstrapping` state.
/// String parameters must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn genesis_inject_secret(
    handle: GenesisHandle,
    secret_name: *const c_char,
    secret_namespace: *const c_char,
    secret_key: *const c_char,
) -> GenesisResult {
    panic::catch_unwind(|| {
        let inner = match take_inner(handle) {
            Ok(i) => i,
            Err(r) => return r,
        };

        let bootstrapping = match inner {
            GenesisInner::Bootstrapping(b) => b,
            other => {
                let handle = inner_to_handle(other);
                return error_with_handle(
                    102,
                    "invalid state: genesis_inject_secret requires Bootstrapping state",
                    handle,
                );
            }
        };

        let name = match parse_c_str(secret_name) {
            Ok(s) => s,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Bootstrapping(bootstrapping));
                return graft_handle(r, handle);
            }
        };
        let ns = match parse_c_str(secret_namespace) {
            Ok(s) => s,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Bootstrapping(bootstrapping));
                return graft_handle(r, handle);
            }
        };
        let key = match parse_c_str(secret_key) {
            Ok(s) => s,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Bootstrapping(bootstrapping));
                return graft_handle(r, handle);
            }
        };

        // TODO(WF-4): Replace MockSecretInjector with UreqSecretInjector
        // for real Kubernetes API server communication.
        let injector = MockSecretInjector::new();

        match bootstrapping.inject_secret(&injector, name, ns, key) {
            Ok(active) => {
                let new_inner = GenesisInner::Active(active);
                success_result(inner_to_handle(new_inner))
            }
            // inject_secret() consumes bootstrapping -- no state to return.
            Err(e) => error_result(e.error_code(), &e.to_string()),
        }
    })
    .unwrap_or_else(|_| panic_result())
}

/// Return a JSON-serialised status snapshot.
///
/// On success, writes JSON to `*status_json_out` (caller must free with
/// `genesis_free_string`), and also sets `data_json` on the result.
///
/// # Safety
///
/// `handle` must be a valid `GenesisHandle` in the `Active` state.
/// `status_json_out` must point to a valid `*mut c_char`.
#[no_mangle]
pub unsafe extern "C" fn genesis_status(
    handle: GenesisHandle,
    status_json_out: *mut *mut c_char,
) -> GenesisResult {
    panic::catch_unwind(|| {
        let inner = match take_inner(handle) {
            Ok(i) => i,
            Err(r) => return r,
        };

        let genesis = match inner {
            GenesisInner::Active(g) => g,
            other => {
                let handle = inner_to_handle(other);
                return error_with_handle(
                    102,
                    "invalid state: genesis_status requires Active state",
                    handle,
                );
            }
        };

        let status = genesis.status();

        // Write to out-parameter if provided.
        if !status_json_out.is_null() {
            match serde_json::to_string(&status) {
                Ok(json) => {
                    let c_json = CString::new(json).unwrap_or_else(|_| CString::new("{}").unwrap());
                    *status_json_out = c_json.into_raw();
                }
                Err(_) => {
                    *status_json_out = ptr::null_mut();
                }
            }
        }

        let json = serde_json::to_string(&status).unwrap_or_default();
        // status() borrows, so we still own genesis.
        let new_inner = GenesisInner::Active(genesis);
        success_result_with_data(inner_to_handle(new_inner), &json)
    })
    .unwrap_or_else(|_| panic_result())
}

/// Begin a key rotation cycle, transitioning to `Rotating`.
///
/// # Safety
///
/// `handle` must be a valid `GenesisHandle` in the `Active` state.
#[no_mangle]
pub unsafe extern "C" fn genesis_begin_rotation(handle: GenesisHandle) -> GenesisResult {
    panic::catch_unwind(|| {
        let inner = match take_inner(handle) {
            Ok(i) => i,
            Err(r) => return r,
        };

        let genesis = match inner {
            GenesisInner::Active(g) => g,
            other => {
                let handle = inner_to_handle(other);
                return error_with_handle(
                    102,
                    "invalid state: genesis_begin_rotation requires Active state",
                    handle,
                );
            }
        };

        let rotating = genesis.begin_rotation();
        let new_inner = GenesisInner::Rotating(rotating);
        success_result(inner_to_handle(new_inner))
    })
    .unwrap_or_else(|_| panic_result())
}

/// Complete the rotation: generate new keypair, re-encrypt, inject,
/// transition to `Active`.
///
/// On success, `data_json` contains JSON-serialised [`PublicArtifacts`].
///
/// # Safety
///
/// `handle` must be a valid `GenesisHandle` in the `Rotating` state.
/// String parameters must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn genesis_complete_rotation(
    handle: GenesisHandle,
    kms_config_json: *const c_char,
    secret_name: *const c_char,
    secret_namespace: *const c_char,
    secret_key: *const c_char,
) -> GenesisResult {
    panic::catch_unwind(|| {
        let inner = match take_inner(handle) {
            Ok(i) => i,
            Err(r) => return r,
        };

        let genesis = match inner {
            GenesisInner::Rotating(g) => g,
            other => {
                let handle = inner_to_handle(other);
                return error_with_handle(
                    102,
                    "invalid state: genesis_complete_rotation requires Rotating state",
                    handle,
                );
            }
        };

        let kms_config = match parse_kms_config(kms_config_json) {
            Ok(c) => c,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Rotating(genesis));
                return graft_handle(r, handle);
            }
        };

        let provider = match create_provider(&kms_config) {
            Ok(p) => p,
            Err(e) => {
                let handle = inner_to_handle(GenesisInner::Rotating(genesis));
                return error_with_handle(e.error_code(), &e.to_string(), handle);
            }
        };

        let name = match parse_c_str(secret_name) {
            Ok(s) => s,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Rotating(genesis));
                return graft_handle(r, handle);
            }
        };
        let ns = match parse_c_str(secret_namespace) {
            Ok(s) => s,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Rotating(genesis));
                return graft_handle(r, handle);
            }
        };
        let key = match parse_c_str(secret_key) {
            Ok(s) => s,
            Err(r) => {
                let handle = inner_to_handle(GenesisInner::Rotating(genesis));
                return graft_handle(r, handle);
            }
        };

        // TODO(WF-4): Replace MockSecretInjector with UreqSecretInjector
        // for real Kubernetes API server communication.
        let injector = MockSecretInjector::new();

        match genesis.complete_rotation(&*provider, &injector, name, ns, key) {
            Ok((active, artifacts)) => {
                let new_inner = GenesisInner::Active(active);
                let json = match serde_json::to_string(&artifacts) {
                    Ok(j) => j,
                    Err(e) => {
                        // Serialization failed but we have the new state.
                        let handle = inner_to_handle(new_inner);
                        return error_with_handle(
                            500,
                            &format!("failed to serialize artifacts: {e}"),
                            handle,
                        );
                    }
                };
                success_result_with_data(inner_to_handle(new_inner), &json)
            }
            // complete_rotation() consumes genesis -- no state to return.
            Err(e) => error_result(e.error_code(), &e.to_string()),
        }
    })
    .unwrap_or_else(|_| panic_result())
}

/// Free a `GenesisHandle` and all associated resources.
///
/// After this call the handle is invalid and must not be used.
/// Passing a NULL pointer is a safe no-op.
///
/// # Safety
///
/// `handle.ptr` must be a valid pointer returned by one of the genesis
/// functions, or NULL.
#[no_mangle]
pub unsafe extern "C" fn genesis_free(handle: GenesisHandle) {
    let result = panic::catch_unwind(|| {
        if !handle.ptr.is_null() {
            // Reconstruct the Box so it is dropped properly.
            let _ = Box::from_raw(handle.ptr as *mut GenesisInner);
        }
    });

    if result.is_err() {
        // Best effort: panic during free is logged but not propagated.
        eprintln!("genesis_free: caught panic during deallocation");
    }
}

/// Free a NUL-terminated string previously returned by genesis-core.
///
/// Passing a NULL pointer is a safe no-op.
///
/// # Safety
///
/// `s` must be a pointer returned by one of the genesis functions (as an
/// error message, data_json, or result string), or NULL.
#[no_mangle]
pub unsafe extern "C" fn genesis_free_string(s: *mut c_char) {
    let result = panic::catch_unwind(|| {
        if !s.is_null() {
            let _ = CString::from_raw(s);
        }
    });

    if result.is_err() {
        eprintln!("genesis_free_string: caught panic during deallocation");
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicArtifacts;

    #[test]
    fn genesis_free_null_is_noop() {
        let handle = GenesisHandle {
            ptr: ptr::null_mut(),
            state: StateTag::Uninitialized,
        };
        // Should not panic or crash.
        unsafe {
            genesis_free(handle);
        }
    }

    #[test]
    fn genesis_free_string_null_is_noop() {
        // Should not panic or crash.
        unsafe {
            genesis_free_string(ptr::null_mut());
        }
    }

    #[test]
    fn genesis_free_string_valid_cstring() {
        let s = CString::new("test error message").expect("CString");
        let raw = s.into_raw();
        // Should free without panic.
        unsafe {
            genesis_free_string(raw);
        }
    }

    #[test]
    fn genesis_free_valid_handle() {
        use crate::audit::NullAuditSink;
        use crate::state::{Genesis, GenesisConfig, Uninitialized};

        let config = GenesisConfig {
            provider_type: "null-dev".to_string(),
            provider_config: serde_json::json!({}),
            public_key: None,
            envelope_ciphertext: None,
        };
        let g = Genesis::<Uninitialized>::new(config, Box::new(NullAuditSink));
        let inner = GenesisInner::Uninitialized(g);
        let handle = inner_to_handle(inner);

        assert_eq!(handle.state, StateTag::Uninitialized);
        assert!(!handle.ptr.is_null());

        // Free should not panic.
        unsafe {
            genesis_free(handle);
        }
    }

    #[test]
    fn inner_state_tags_are_correct() {
        use crate::audit::NullAuditSink;
        use crate::state::{Genesis, GenesisConfig, Uninitialized};

        let config = GenesisConfig {
            provider_type: "test".to_string(),
            provider_config: serde_json::json!({}),
            public_key: None,
            envelope_ciphertext: None,
        };
        let g = Genesis::<Uninitialized>::new(config, Box::new(NullAuditSink));
        let inner = GenesisInner::Uninitialized(g);
        assert_eq!(inner.state_tag(), StateTag::Uninitialized);
    }

    #[test]
    fn error_result_has_message() {
        let result = error_result(42, "test error");
        assert!(!result.success);
        assert_eq!(result.error_code, 42);
        assert!(!result.error_message.is_null());
        assert!(result.data_json.is_null());

        // Clean up.
        unsafe {
            genesis_free_string(result.error_message);
        }
    }

    #[test]
    fn success_result_has_null_message() {
        let handle = GenesisHandle {
            ptr: ptr::null_mut(),
            state: StateTag::Active,
        };
        let result = success_result(handle);
        assert!(result.success);
        assert_eq!(result.error_code, 0);
        assert!(result.error_message.is_null());
        assert!(result.data_json.is_null());
    }

    #[test]
    fn success_result_with_data_has_json() {
        let handle = GenesisHandle {
            ptr: ptr::null_mut(),
            state: StateTag::Active,
        };
        let result = success_result_with_data(handle, r#"{"key":"value"}"#);
        assert!(result.success);
        assert!(!result.data_json.is_null());

        // Verify the JSON string content.
        unsafe {
            let json_str = CStr::from_ptr(result.data_json)
                .to_str()
                .expect("valid UTF-8");
            assert_eq!(json_str, r#"{"key":"value"}"#);
            genesis_free_string(result.data_json);
        }
    }

    // ── FFI lifecycle tests ──────────────────────────────────────────

    fn mock_config_json() -> CString {
        CString::new(
            serde_json::json!({
                "provider_type": "mock",
                "provider_config": {},
                "public_key": null,
                "envelope_ciphertext": null
            })
            .to_string(),
        )
        .unwrap()
    }

    fn mock_kms_config_json() -> CString {
        CString::new(
            serde_json::json!({
                "provider_type": "mock"
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn ffi_genesis_new_creates_handle() {
        let config = mock_config_json();
        let result = unsafe { genesis_new(config.as_ptr(), None) };
        assert!(result.success, "genesis_new should succeed");
        assert_eq!(result.handle.state, StateTag::Uninitialized);
        assert!(!result.handle.ptr.is_null());

        unsafe { genesis_free(result.handle) };
    }

    #[test]
    fn ffi_genesis_new_with_bad_json() {
        let bad = CString::new("not json").unwrap();
        let result = unsafe { genesis_new(bad.as_ptr(), None) };
        assert!(!result.success);
        assert_eq!(result.error_code, 500);

        unsafe { genesis_free_string(result.error_message) };
    }

    #[test]
    fn ffi_genesis_new_with_null_config() {
        let result = unsafe { genesis_new(ptr::null(), None) };
        assert!(!result.success);
        assert_eq!(result.error_code, 1);

        unsafe { genesis_free_string(result.error_message) };
    }

    #[test]
    fn ffi_full_lifecycle() {
        // new -> init -> begin_bootstrap -> inject -> status -> begin_rotation -> complete_rotation
        let config = mock_config_json();
        let kms_config = mock_kms_config_json();

        // 1. genesis_new
        let r = unsafe { genesis_new(config.as_ptr(), None) };
        assert!(r.success);
        let handle = r.handle;

        // 2. genesis_init
        let r = unsafe { genesis_init(handle, kms_config.as_ptr()) };
        assert!(r.success, "genesis_init should succeed");
        assert_eq!(r.handle.state, StateTag::Initialized);
        assert!(!r.data_json.is_null(), "init should return artifacts JSON");

        // Parse the artifacts to verify structure.
        let artifacts_json = unsafe { CStr::from_ptr(r.data_json).to_str().unwrap().to_string() };
        let artifacts: PublicArtifacts =
            serde_json::from_str(&artifacts_json).expect("artifacts JSON should parse");
        assert!(artifacts.public_key.starts_with("age1"));
        assert!(!artifacts.envelope_ciphertext.is_empty());
        unsafe { genesis_free_string(r.data_json) };
        let handle = r.handle;

        // 3. genesis_begin_bootstrap
        let r = unsafe { genesis_begin_bootstrap(handle, kms_config.as_ptr()) };
        assert!(r.success, "genesis_begin_bootstrap should succeed");
        assert_eq!(r.handle.state, StateTag::Bootstrapping);
        let handle = r.handle;

        // 4. genesis_inject_secret
        let name = CString::new("genesis-key").unwrap();
        let ns = CString::new("genesis-system").unwrap();
        let key = CString::new("age.key").unwrap();
        let r = unsafe { genesis_inject_secret(handle, name.as_ptr(), ns.as_ptr(), key.as_ptr()) };
        assert!(r.success, "genesis_inject_secret should succeed");
        assert_eq!(r.handle.state, StateTag::Active);
        let handle = r.handle;

        // 5. genesis_status
        let mut status_out: *mut c_char = ptr::null_mut();
        let r = unsafe { genesis_status(handle, &mut status_out) };
        assert!(r.success, "genesis_status should succeed");
        assert_eq!(r.handle.state, StateTag::Active);
        assert!(!r.data_json.is_null());
        assert!(!status_out.is_null());

        let status_str = unsafe { CStr::from_ptr(status_out).to_str().unwrap() };
        assert!(status_str.contains("active"));
        unsafe {
            genesis_free_string(status_out);
            genesis_free_string(r.data_json);
        }
        let handle = r.handle;

        // 6. genesis_begin_rotation
        let r = unsafe { genesis_begin_rotation(handle) };
        assert!(r.success, "genesis_begin_rotation should succeed");
        assert_eq!(r.handle.state, StateTag::Rotating);
        let handle = r.handle;

        // 7. genesis_complete_rotation
        let r = unsafe {
            genesis_complete_rotation(
                handle,
                kms_config.as_ptr(),
                name.as_ptr(),
                ns.as_ptr(),
                key.as_ptr(),
            )
        };
        assert!(r.success, "genesis_complete_rotation should succeed");
        assert_eq!(r.handle.state, StateTag::Active);
        assert!(!r.data_json.is_null());

        let new_artifacts_json =
            unsafe { CStr::from_ptr(r.data_json).to_str().unwrap().to_string() };
        let new_artifacts: PublicArtifacts =
            serde_json::from_str(&new_artifacts_json).expect("new artifacts JSON should parse");
        assert!(new_artifacts.public_key.starts_with("age1"));
        // New key should differ from old key.
        assert_ne!(new_artifacts.public_key, artifacts.public_key);

        unsafe {
            genesis_free_string(r.data_json);
            genesis_free(r.handle);
        }
    }

    #[test]
    fn ffi_genesis_load() {
        let config = mock_config_json();
        let r = unsafe { genesis_new(config.as_ptr(), None) };
        assert!(r.success);

        let pk = CString::new("age1testkey").unwrap();
        let envelope: &[u8] = &[1u8, 2, 3, 4, 5];

        let r = unsafe { genesis_load(r.handle, pk.as_ptr(), envelope.as_ptr(), envelope.len()) };
        assert!(r.success, "genesis_load should succeed");
        assert_eq!(r.handle.state, StateTag::Initialized);

        unsafe { genesis_free(r.handle) };
    }

    #[test]
    fn ffi_genesis_verify() {
        let config = mock_config_json();
        let kms_config = mock_kms_config_json();

        let r = unsafe { genesis_new(config.as_ptr(), None) };
        assert!(r.success);

        let r = unsafe { genesis_init(r.handle, kms_config.as_ptr()) };
        assert!(r.success);
        unsafe { genesis_free_string(r.data_json) };

        let mut result_out: *mut c_char = ptr::null_mut();
        let r = unsafe { genesis_verify(r.handle, kms_config.as_ptr(), &mut result_out) };
        assert!(r.success, "genesis_verify should succeed");
        assert_eq!(r.handle.state, StateTag::Initialized);
        assert!(!result_out.is_null());
        assert!(!r.data_json.is_null());

        let verify_str = unsafe { CStr::from_ptr(result_out).to_str().unwrap() };
        assert!(verify_str.contains("public_key_matches"));

        unsafe {
            genesis_free_string(result_out);
            genesis_free_string(r.data_json);
            genesis_free(r.handle);
        }
    }

    #[test]
    fn ffi_wrong_state_returns_error_and_preserves_handle() {
        let config = mock_config_json();
        let kms_config = mock_kms_config_json();

        // Create in Uninitialized state.
        let r = unsafe { genesis_new(config.as_ptr(), None) };
        assert!(r.success);

        // Try to begin_bootstrap (requires Initialized) -- should fail
        // but the handle must be returned so Go can recover it.
        let r = unsafe { genesis_begin_bootstrap(r.handle, kms_config.as_ptr()) };
        assert!(!r.success);
        assert_eq!(r.error_code, 102);
        assert!(
            !r.handle.ptr.is_null(),
            "wrong-state error must return a non-null handle"
        );
        assert_eq!(
            r.handle.state,
            StateTag::Uninitialized,
            "handle should still be in the original state"
        );

        // The handle is still usable -- free it to prove no double-free.
        unsafe {
            genesis_free_string(r.error_message);
            genesis_free(r.handle);
        }
    }

    #[test]
    fn ffi_wrong_state_handle_is_reusable() {
        let config = mock_config_json();
        let kms_config = mock_kms_config_json();

        // Create in Uninitialized state.
        let r = unsafe { genesis_new(config.as_ptr(), None) };
        assert!(r.success);

        // Wrong-state call returns the handle.
        let r = unsafe { genesis_begin_bootstrap(r.handle, kms_config.as_ptr()) };
        assert!(!r.success);
        assert_eq!(r.error_code, 102);
        unsafe { genesis_free_string(r.error_message) };

        // Use the recovered handle for a valid operation (genesis_init).
        let r = unsafe { genesis_init(r.handle, kms_config.as_ptr()) };
        assert!(
            r.success,
            "recovered handle should be usable for genesis_init"
        );
        assert_eq!(r.handle.state, StateTag::Initialized);

        unsafe {
            genesis_free_string(r.data_json);
            genesis_free(r.handle);
        }
    }
}
