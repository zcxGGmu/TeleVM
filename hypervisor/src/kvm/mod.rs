// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use kvm_bindings::kvm_userspace_memory_region as MemorySlot;
use kvm_bindings::*;
use kvm_ioctls::{Kvm, VmFd};
use log::error;
use once_cell::sync::Lazy;
use vmm_sys_util::{
     ioctl_io_nr, ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr,
};

use anyhow::{Context, Result};

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/kvm.h
pub const KVM_SET_DEVICE_ATTR: u32 = 0x4018_aee1;
pub const KVM_SET_USER_MEMORY_REGION: u32 = 0x4020_ae46;
pub const KVM_IOEVENTFD: u32 = 0x4040_ae79;
pub const KVM_SIGNAL_MSI: u32 = 0x4020_aea5;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/kvm.h
ioctl_io_nr!(KVM_GET_API_VERSION, KVMIO, 0x00);
ioctl_ior_nr!(KVM_GET_MP_STATE, KVMIO, 0x98, kvm_mp_state);
ioctl_ior_nr!(KVM_GET_REGS, KVMIO, 0x81, kvm_regs);
ioctl_ior_nr!(KVM_GET_SREGS, KVMIO, 0x83, kvm_sregs);
ioctl_iow_nr!(KVM_GET_ONE_REG, KVMIO, 0xab, kvm_one_reg);
ioctl_iow_nr!(KVM_SET_ONE_REG, KVMIO, 0xac, kvm_one_reg);
ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KVMFds {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<VmFd>,
    pub mem_slots: Arc<Mutex<HashMap<u32, MemorySlot>>>,
}

impl KVMFds {
    pub fn new() -> Self {
        match Kvm::new() {
            Ok(fd) => {
                let vm_fd = match fd.create_vm() {
                    Ok(vm_fd) => vm_fd,
                    Err(e) => {
                        error!("Failed to create VM in KVM: {}", e);
                        return KVMFds::default();
                    }
                };
                KVMFds {
                    fd: Some(fd),
                    vm_fd: Some(vm_fd),
                    mem_slots: Arc::new(Mutex::new(HashMap::new())),
                }
            }
            Err(e) => {
                error!("Failed to open /dev/kvm: {}", e);
                KVMFds::default()
            }
        }
    }

    /// Start dirty page tracking in kvm.
    pub fn start_dirty_log(&self) -> Result<()> {
        for (_, region) in self.mem_slots.lock().unwrap().iter_mut() {
            region.flags = KVM_MEM_LOG_DIRTY_PAGES;
            // Safe because region from `KVMFds` is reliable.
            unsafe {
                self.vm_fd
                    .as_ref()
                    .unwrap()
                    .set_user_memory_region(*region)
                    .with_context(|| {
                        format!(
                            "Failed to start dirty log, error is {}",
                            std::io::Error::last_os_error()
                        )
                    })?;
            }
        }

        Ok(())
    }

    /// Stop dirty page tracking in kvm.
    pub fn stop_dirty_log(&self) -> Result<()> {
        for (_, region) in self.mem_slots.lock().unwrap().iter_mut() {
            region.flags = 0;
            // Safe because region from `KVMFds` is reliable.
            unsafe {
                self.vm_fd
                    .as_ref()
                    .unwrap()
                    .set_user_memory_region(*region)
                    .with_context(|| {
                        format!(
                            "Failed to stop dirty log, error is {}",
                            std::io::Error::last_os_error()
                        )
                    })?;
            }
        }

        Ok(())
    }

    /// Get dirty page bitmap in kvm.
    pub fn get_dirty_log(&self, slot: u32, mem_size: u64) -> Result<Vec<u64>> {
        let res = self
            .vm_fd
            .as_ref()
            .unwrap()
            .get_dirty_log(slot, mem_size as usize)
            .with_context(|| {
                format!(
                    "Failed to get dirty log, error is {}",
                    std::io::Error::last_os_error()
                )
            })?;

        Ok(res)
    }

    /// Add ram memory region to `KVMFds` structure.
    pub fn add_mem_slot(&self, mem_slot: MemorySlot) -> Result<()> {
        if mem_slot.flags & KVM_MEM_READONLY != 0 {
            return Ok(());
        }

        let mut locked_slots = self.mem_slots.as_ref().lock().unwrap();
        locked_slots.insert(mem_slot.slot, mem_slot);

        Ok(())
    }

    /// Remove ram memory region from `KVMFds` structure.
    pub fn remove_mem_slot(&self, mem_slot: MemorySlot) -> Result<()> {
        let mut locked_slots = self.mem_slots.as_ref().lock().unwrap();
        locked_slots.remove(&mem_slot.slot);

        Ok(())
    }

    /// Get ram memory region from `KVMFds` structure.
    pub fn get_mem_slots(&self) -> Arc<Mutex<HashMap<u32, MemorySlot>>> {
        self.mem_slots.clone()
    }
}

pub static KVM_FDS: Lazy<ArcSwap<KVMFds>> = Lazy::new(|| ArcSwap::from(Arc::new(KVMFds::new())));
