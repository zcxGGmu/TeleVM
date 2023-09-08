extern crate kvm_bindings;
extern crate libc;
#[macro_use]
extern crate vmm_sys_util;

#[macro_use]
mod kvm_ioctls;
mod cap;
mod ioctls;

pub use cap::Cap;
pub use ioctls::device::DeviceFd;
pub use ioctls::system::Kvm;
pub use ioctls::vcpu::{VcpuExit, VcpuFd};

pub use ioctls::vm::{IoEventAddress, NoDatamatch, VmFd};
// The following example is used to verify that our public
// structures are exported properly.
/// # Example
///
/// ```
/// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// use kvm_ioctls::{Error, KvmRunWrapper};
/// ```
pub use ioctls::KvmRunWrapper;
pub use vmm_sys_util::errno::Error;
