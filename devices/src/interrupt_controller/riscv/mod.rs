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

pub mod plic;
pub use plic::PLIC;

use std::sync::{Arc, Mutex};
use sysbus::SysBus;
use kvm_ioctls::VcpuFd;
use anyhow::{anyhow, Context, Result};

/// PLIC version type.
pub enum PLICVersion {
    PLIC,
 }

 pub struct PLICConfig {
    /// Config PLIC version
    pub version: Option<PLICVersion>,
    /// Config number of CPUs handled by the device
    pub vcpu_count: u32,
    pub region_base: u64,
    pub region_size: u64,
}

pub trait PLICDevice {
    fn new() -> Self
    where
        Self: Sized;
    
    fn kvm_irq_line(&self, irq: u8, level: u8) -> Result<()>;

    fn kvm_irq_trigger(&self, irq: u8) -> Result<()>;
}

/// A wrapper around creating and using a interrupt controller.
pub struct InterruptController {
    plic: Arc<Mutex<dyn PLICDevice + std::marker::Send + std::marker::Sync>>,
}

impl InterruptController {
    pub fn new(vcpu_fds: Vec<Arc<VcpuFd>>, sysbus: &mut SysBus, config: &PLICConfig) -> Result<InterruptController> {
        let intc = match &config.version {
            Some(PLICVersion::PLIC) => {
                let plic = PLIC::new().realize(vcpu_fds, sysbus, config)?;
                InterruptController {
                    plic: plic,
                }
            },
            None => {
                let plic = PLIC::new().realize(vcpu_fds, sysbus, config)?;
                InterruptController {
                    plic: plic,
                }
            },
        };
        Ok(intc)
    }

    pub fn kvm_irq_line(&self, irq: u8, level: u8) -> Result<()> {
        self.plic.lock().unwrap().kvm_irq_line(irq, level)?;
        Ok(())
    }

    pub fn kvm_irq_trigger(&self, irq: u8) -> Result<()> {
        self.plic.lock().unwrap().kvm_irq_trigger(irq)?;
        Ok(())
    }

}

