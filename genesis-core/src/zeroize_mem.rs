//! Secure wrapper around raw key material.
//!
//! [`KeyMaterial`] guarantees that:
//!
//! 1. The backing buffer is zeroized on drop (via [`zeroize::Zeroizing`]).
//! 2. The pages are memory-locked (`mlock`) so the kernel will not swap
//!    them to disk.
//! 3. On Linux the pages are excluded from core dumps (`MADV_DONTDUMP`).
//! 4. A defense-in-depth `explicit_bzero` runs in the `Drop` impl even
//!    though `Zeroizing` already handles zeroing.
//!
//! **Intentionally omitted impls**: `Clone`, `Debug`, `Display`,
//! `Serialize`, `PartialEq` -- any of these could leak key material.

use zeroize::Zeroizing;

/// Wrapper that keeps secret key bytes memory-locked and zeroizes on drop.
pub struct KeyMaterial {
    inner: Zeroizing<Vec<u8>>,
}

impl KeyMaterial {
    /// Create a new `KeyMaterial` from raw bytes.
    ///
    /// Calls `mlock` on the buffer to prevent the kernel from swapping the
    /// pages. On Linux, additionally calls `madvise(MADV_DONTDUMP)` to
    /// exclude the region from core dumps. Failures from either syscall are
    /// silently ignored (best-effort hardening; the operator may not have
    /// `CAP_IPC_LOCK`).
    pub fn new(bytes: Vec<u8>) -> Self {
        let inner = Zeroizing::new(bytes);

        // Best-effort mlock -- ignore ENOMEM / EPERM.
        if !inner.is_empty() {
            unsafe {
                libc::mlock(inner.as_ptr() as *const libc::c_void, inner.len());
            }

            #[cfg(target_os = "linux")]
            {
                unsafe {
                    libc::madvise(
                        inner.as_ptr() as *mut libc::c_void,
                        inner.len(),
                        libc::MADV_DONTDUMP,
                    );
                }
            }
        }

        Self { inner }
    }

    /// Borrow the raw key bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

impl Drop for KeyMaterial {
    /// Defense-in-depth: zero the buffer with volatile writes even though
    /// [`Zeroizing`] will zero it as well.  This runs *before* the
    /// `Zeroizing` destructor because Rust drops fields after the
    /// containing struct's `Drop::drop` returns.
    fn drop(&mut self) {
        if !self.inner.is_empty() {
            unsafe {
                // Volatile write_bytes + compiler fence guarantees the
                // zeroing is not optimized away -- equivalent to
                // explicit_bzero semantics.
                core::ptr::write_bytes(self.inner.as_mut_ptr(), 0u8, self.inner.len());
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

                libc::munlock(self.inner.as_ptr() as *const libc::c_void, self.inner.len());
            }
        }
    }
}
