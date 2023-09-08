// Copyright (c) 2023 China Telecom Co.,Ltd. All rights reserved.
//
// TeleVM is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
//
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

pub mod caps;
mod core_regs;

pub use self::caps::RISCVCPUCaps;
use kvm_bindings::{
    kvm_mp_state, kvm_riscv_config, kvm_riscv_core, kvm_riscv_timer, KVM_MP_STATE_RUNNABLE,
    KVM_MP_STATE_STOPPED,
};
use kvm_ioctls::VcpuFd;
use std::sync::{Arc, Mutex};

use self::core_regs::{get_config_regs, get_timer_regs, set_core_regs};
use anyhow::{Context, Result};

use migration::{
    DeviceStateDesc, FieldDesc,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;

/// RISCV CPU booting configure information
#[derive(Default, Copy, Clone, Debug)]
pub struct RISCVCPUBootConfig {
    pub fdt_addr: u64,
    pub boot_pc: u64,
}

#[allow(dead_code)]
#[derive(Default, Copy, Clone, Debug)]
pub struct RISCVCPUTopology {
    threads: u8,
    cores: u8,
    clusters: u8,
}

impl RISCVCPUTopology {
    pub fn new() -> Self {
        RISCVCPUTopology::default()
    }

    pub fn set_topology(self, _topology: (u8, u8, u8)) -> Self {
        self
    }
}

/// RISCV CPU architect information
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct RISCVCPUState {
    /// The vcpu id, `0` means primary CPU.
    apic_id: u32,
    /// Vcpu config registers.
    config_regs: kvm_riscv_config,
    /// Vcpu core registers.
    core_regs: kvm_riscv_core,
    /// Vcpu timer registers.
    timer_regs: kvm_riscv_timer,
    /// Vcpu mpstate register.
    mp_state: kvm_mp_state,
    /// The length of registers
    xlen: u64,
}

impl RISCVCPUState {
    /// Allocates a new `RISCVCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - ID of this `CPU`.
    pub fn new(vcpu_id: u32) -> Self {
        let mp_state = kvm_mp_state {
            mp_state: if vcpu_id == 0 {
                KVM_MP_STATE_RUNNABLE
            } else {
                KVM_MP_STATE_STOPPED
            },
        };

        RISCVCPUState {
            apic_id: vcpu_id,
            mp_state,
            xlen: 64,
            ..Default::default()
        }
    }

    pub fn set(&mut self, cpu_state: &Arc<Mutex<RISCVCPUState>>) {
        let locked_cpu_state = cpu_state.lock().unwrap();
        self.apic_id = locked_cpu_state.apic_id;
        self.core_regs = locked_cpu_state.core_regs;
        self.mp_state = locked_cpu_state.mp_state;
    }

    /// Set register value in `RISCVCPUState` according to `boot_config`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    /// * `boot_config` - Boot message from boot_loader.
    pub fn set_boot_config(
        &mut self,
        vcpu_fd: &Arc<VcpuFd>,
        boot_config: &RISCVCPUBootConfig,
    ) -> Result<()> {
        self.config_regs = get_config_regs(vcpu_fd)?;
        self.timer_regs = get_timer_regs(vcpu_fd)?;

        self.set_core_reg(boot_config);

        Ok(())
    }

    /// Set cpu topology
    ///
    /// # Arguments
    ///
    /// * `topology` - RISCV CPU Topology
    pub fn set_cpu_topology(&mut self, _topology: &RISCVCPUTopology) -> Result<()> {
        Ok(())
    }

    /// Reset register value in `Kvm` with `RISCVCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    pub fn reset_vcpu(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        set_core_regs(vcpu_fd, self.core_regs)
            .with_context(|| format!("Failed to set core register for CPU {}", self.apic_id))?;
        vcpu_fd
            .set_mp_state(self.mp_state)
            .with_context(|| format!("Failed to set mpstate for CPU {}", self.apic_id))?;
        Ok(())
    }

    /// Get config_regs value.
    pub fn config_regs(&self) -> kvm_riscv_config {
        self.config_regs
    }

    /// Get core_regs value.
    pub fn core_regs(&self) -> kvm_riscv_core {
        self.core_regs
    }

    /// Get timer_regs value.
    pub fn timer_regs(&self) -> kvm_riscv_timer {
        self.timer_regs
    }

    /// Set core registers.
    fn set_core_reg(&mut self, boot_config: &RISCVCPUBootConfig) {
        // Set vcpu id.
        self.core_regs.regs.a0 = self.apic_id as u64;

        // Configure boot ip and device tree address, prepare for kernel setup
        if self.apic_id == 0 {
            self.core_regs.regs.a1 = boot_config.fdt_addr;
            self.core_regs.regs.pc = boot_config.boot_pc;
        }
    }

    /// Get the length of registers.
    pub fn get_xlen(&self) -> u64 {
        self.xlen
    }
}
