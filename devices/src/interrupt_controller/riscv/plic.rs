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

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use sysbus::{SysBus, SysBusDevOps, SysBusDevType, SysRes};
use address_space::GuestAddress;
use kvm_ioctls::VcpuFd;
use super::{PLICConfig, PLICDevice};
use log::{debug, error};

pub const MAX_DEVICES: u32 = 1024;
const MAX_CONTEXTS: u32 = 15872; 

const PRIORITY_BASE: u32 = 0;
const PRIORITY_PER_ID: u32 =4;
 
const ENABLE_BASE: u32 = 0x2000;
const ENABLE_PER_HART: u32 = 0x80;

const CONTEXT_BASE: u32 = 0x0020_0000;
const CONTEXT_PER_HART: u32 = 0x1000;
const CONTEXT_THRESHOLD: u32 = 0;
const CONTEXT_CLAIM: u32 = 4;

const REG_SIZE: u32 = 0x0100_0000; 


#[derive(Clone,Debug)]
struct PLICContext{
    num: u32,
    irq_priority_threshold: u8,
    vcpu_fd: Arc<VcpuFd>,
    irq_enable: [u32; (MAX_DEVICES/32) as usize],
    irq_pending: [u32; (MAX_DEVICES/32) as usize],
    irq_pending_priority: [u8; MAX_DEVICES as usize],
    irq_claimed: [u32; (MAX_DEVICES/32) as usize],
    irq_autoclear: [u32; (MAX_DEVICES/32) as usize],
}


impl PLICContext {
    fn new(vcpu_fd:Arc<VcpuFd>) -> Self {
        Self {
           num: 0,
           irq_priority_threshold: 0,
           vcpu_fd: vcpu_fd,
           irq_enable: [0; (MAX_DEVICES/32) as usize],
           irq_pending: [0; (MAX_DEVICES/32) as usize],
           irq_pending_priority: [0; MAX_DEVICES as usize],
           irq_claimed: [0; (MAX_DEVICES/32) as usize],
           irq_autoclear: [0; (MAX_DEVICES/32) as usize]
        }
    }
}


pub struct PLIC {
    ready: bool,
    num_irq: u32,
    num_irq_word:u32,
    max_prio:u32,

    num_context:u32,
    contexts:Vec<Arc<Mutex<PLICContext>>>,

    irq_priority: [u8; MAX_DEVICES as usize],
    /// System resource.
    res: SysRes,
}

impl PLICDevice for PLIC {
    fn new() -> Self {
        PLIC {
            ready: false,
            num_irq: MAX_DEVICES,
            num_irq_word: MAX_DEVICES,
            max_prio: (1 << PRIORITY_PER_ID) - 1,
            num_context: MAX_CONTEXTS,
            contexts: Vec::<Arc<Mutex<PLICContext>>>::new(),
            irq_priority: [0; MAX_DEVICES as usize],
            /// System resource.
            res: SysRes::default(),
        }
        
    }

    fn kvm_irq_line(&self, irq: u8, level: u8) -> Result<()> {
        self.plic_irq_trig(irq, level, false)?;
        Ok(())
    }

    fn kvm_irq_trigger(&self, irq: u8) -> Result<()> {
        self.plic_irq_trig(irq, 1, true)?;
        Ok(())
    }
}

impl PLIC {
    pub fn realize(mut self, 
        vcpu_fds: Vec<Arc<VcpuFd>>,
        sysbus: &mut SysBus,
        plic_conf: &PLICConfig,
    ) -> Result<Arc<Mutex<Self>>> {    

        self.num_irq_word = self.num_irq / 32;
        if self.num_irq_word * 32 < self.num_irq{
            self.num_irq_word += 1;
        }

        self.num_context = plic_conf.vcpu_count * 2;
        
        let mut contexts = Vec::<Arc<Mutex<PLICContext>>>::new();
        for i in 0..self.num_context {
            let vcpu_fd = vcpu_fds[(i / 2) as usize].clone();
            let mut context = PLICContext::new(vcpu_fd);
            context.num = i;
            contexts.push(Arc::new(Mutex::new(context)));
        }
        self.contexts = contexts;
       
        let region_base = plic_conf.region_base;
        let region_size = plic_conf.region_size;

        if let Some(res) = self.get_sys_resource() {
            res.region_base = region_base;
            res.region_size = region_size;
            res.irq = 0;
        }

        self.ready = true;
        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size).with_context(|| "Failed to attach device")?;

        Ok(dev)
    }

    fn context_best_pending_irq(&self, context: &Arc<Mutex<PLICContext>>) -> Result<u32> {
        let mut best_irq_prio = 0;
        let mut best_irq:u32 = 0;
        let mut i = 0;
        while i < self.num_irq_word {
            let context= context.lock().unwrap();
            if context.irq_pending[i as usize] == 0 {
                i += 1;
                continue;
            }

            let mut j = 0;
            while j < 32 {
                let irq = i * 32 + j;
                if (self.num_irq <= irq) ||
                ((context.irq_pending[i as usize] & (1 << j) ) == 0) ||
                ((context.irq_claimed[i as usize] & (1 << j)) != 0) {
                    j += 1;
                    continue;
                }
                if (best_irq == 0) || (best_irq_prio < context.irq_pending_priority[irq as usize]) {
                    best_irq = irq;
                    best_irq_prio = context.irq_pending_priority[irq as usize];
                }
                j += 1;
            }
            i += 1;
        }

        Ok(best_irq)
    }

    fn context_irq_update(&self, context: &Arc<Mutex<PLICContext>>) -> Result<()> {
        let vcpu_fd = context.lock().unwrap().vcpu_fd.clone();
        let best_irq = self.context_best_pending_irq(context)?;
        if best_irq > 0 {
            vcpu_fd.set_interrupt();
        } 
        else {
            vcpu_fd.unset_interrupt();
        };
        
        Ok(())
    }

    pub fn plic_irq_trig(&self, irq: u8, level: u8, edge: bool) -> Result<()> {
        let mut irq_marked = false;
        
        if !self.ready {return Ok(());}

        let irq_prio = self.irq_priority[irq as usize];
        let irq_word = (irq / 32) as usize;
        let irq_mask = 1 << (irq % 32);

        let mut i = 0;
        while i < self.num_context {
            let mut context = self.contexts[i as usize].lock().unwrap();
            if (context.irq_enable[irq_word] & irq_mask) != 0 {
                if level != 0 {
                    context.irq_pending[irq_word] |= irq_mask;
                    context.irq_pending_priority[irq as usize] = irq_prio;
                    if edge{
                        context.irq_autoclear[irq_word] |= irq_mask;
                    }
                }
                else {
                    context.irq_pending[irq_word] &= !irq_mask;
                    context.irq_pending_priority[irq as usize] = 0;
                    context.irq_claimed[irq_word] &= !irq_mask;
                    context.irq_autoclear[irq_word] &= !irq_mask;
                }
                self.context_irq_update(&Arc::new(Mutex::new(context.clone())))?;
                irq_marked = true;
            }
            if irq_marked {break;}
            i += 1;
        }

        Ok(())
    }

    fn context_irq_claim(&self, context: &Arc<Mutex<PLICContext>>) -> Result<u32> {
        let vcpu_fd = context.lock().unwrap().vcpu_fd.clone();
        let best_irq = self.context_best_pending_irq(context)?;
        let best_irq_word = best_irq / 32;
        let best_irq_mask = 1 << (best_irq % 32);

        vcpu_fd.unset_interrupt();

        let mut context = context.lock().unwrap();
        if best_irq > 0 {
            if (context.irq_autoclear[best_irq_word as usize] & best_irq_mask) != 0 {
                context.irq_pending[best_irq_word as usize] &= !best_irq_mask;
                context.irq_pending_priority[best_irq as usize] = 0;
                context.irq_claimed[best_irq_word as usize] &= !best_irq_mask;
                context.irq_autoclear[best_irq_word as usize] &= !best_irq_mask;
            }
            else {
                context.irq_claimed[best_irq_word as usize] |= best_irq_mask;
            }
        }

        self.context_irq_update(&Arc::new(Mutex::new(context.clone())))?;
        Ok(best_irq)
    }

    fn priority_read(&self, offset: u32, data: &mut [u8]) -> Result<()> {
        let irq:u32 = offset >> 2;
        if (irq == 0) || (irq >= self.num_irq)  {return Ok(());}
        data[0] = self.irq_priority[irq as usize];
        Ok(())
    }

    fn priority_write(&mut self, offset: u32, data: &[u8]) -> Result<()> {
        let irq:u32 = offset >> 2;
        if (irq == 0) || (irq >= self.num_irq)  {return Ok(());}
        let mut val= data[0];
        val &= (1 << PRIORITY_PER_ID) - 1;
        self.irq_priority[irq as usize] = val ;
        Ok(())
    }

    fn context_enable_read(&self, context: &Arc<Mutex<PLICContext>>, offset: u32, data: &mut [u8]) -> Result<()> {
        let irq_word:u32 = offset >> 2;
        if self.num_irq_word < irq_word   {return Ok(());}
        data[0] = context.lock().unwrap().irq_enable[irq_word as usize] as u8;
        Ok(())
    }

    fn context_enable_write(&self, context: &Arc<Mutex<PLICContext>>, offset: u32, data: &[u8]) -> Result<()> {
        let irq_word:u32 = offset >> 2;

        if self.num_irq_word < irq_word  {return Ok(());}

        let mut context = context.lock().unwrap();

        let old_val:u32 = context.irq_enable[irq_word as usize];
        let mut new_val= data[0] as u32;
        if irq_word == 0 {
            new_val &= !0x1;
        }
        context.irq_enable[irq_word as usize] = new_val;

        let xor_val:u32 = old_val ^ new_val;
        let mut i = 0;
        while i < 32 {
            let irq = irq_word * 32 + i;
            let irq_mask:u32 = 1 << i;
            let irq_prio:u8 = self.irq_priority[irq as usize];
            if (xor_val & irq_mask) == 0 {
                i += 1;
                continue;
            }
            if (new_val & irq_mask) == 0{
                context.irq_pending[irq_word as usize] &= !irq_mask;
                context.irq_pending_priority[irq as usize] = 0;
                context.irq_claimed[irq_word as usize] &= !irq_mask;
            }
            i += 1;
        }

        self.context_irq_update(&Arc::new(Mutex::new(context.clone())))?;
        Ok(())
    }

    fn context_read(&self, context: &Arc<Mutex<PLICContext>>, offset: u32, data: &mut [u8]) -> Result<()> {
        match offset {
            CONTEXT_THRESHOLD=> {
                data[0] = context.lock().unwrap().irq_priority_threshold;
            } 
            CONTEXT_CLAIM => {
                data[0] = self.context_irq_claim(context).unwrap() as u8;
            }
            _ => ()
        }
        Ok(())
    }
 
    fn context_write(&self, context: &Arc<Mutex<PLICContext>>, offset: u32, data: &[u8]) -> Result<()> {
        let mut irq_update = false;
        match offset {
            CONTEXT_THRESHOLD => {
                let mut val= data[0] as u32;
                val &= (1 << PRIORITY_PER_ID) - 1;
                if val <= self.max_prio {
                    context.lock().unwrap().irq_priority_threshold = val as u8;
                }
                else {
                    irq_update = true;
                }
            }
            CONTEXT_CLAIM =>{
                let val= data[0] as u32;
                let irq_word = val / 32;
                let irq_mask = 1 << (val % 32);
                if (val < self.num_irq) && 
                    ((context.lock().unwrap().irq_enable[irq_word as usize] & irq_mask) != 0) {
                            context.lock().unwrap().irq_claimed[irq_word as usize] &= !irq_mask;
                            irq_update = true;
                }
            }
            _ =>{
                irq_update = true;
            }
        }
        if irq_update {
            self.context_irq_update(context)?;
        }
        Ok(())
    }

}

impl SysBusDevOps for PLIC {
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let mut addr = offset as u32;
        addr &= !0x3;
        if PRIORITY_BASE <= addr && addr < ENABLE_BASE {
            if self.priority_read(addr, data).is_err() {
                error!("Failed to read priority register");
                return false;
            }
        }
        else if ENABLE_BASE <= addr && addr < CONTEXT_BASE {
            let cntx:u32 = (addr - ENABLE_BASE) / ENABLE_PER_HART;
            addr -= cntx * ENABLE_PER_HART + ENABLE_BASE;
            if cntx < self.num_context  {
                if self.context_enable_read(self.contexts.get(cntx as usize).unwrap(), addr, data).is_err() {
                    error!("Failed to read enable register");
                    return false;
                }
            } 
        }
        else if CONTEXT_BASE <= addr && addr < REG_SIZE {
            let cntx:u32 = (addr - CONTEXT_BASE) / CONTEXT_PER_HART;
            addr -= cntx * CONTEXT_PER_HART + CONTEXT_BASE;
            if cntx < self.num_context {
               if self.context_read(self.contexts.get(cntx as usize).unwrap(), addr, data).is_err() {
                    error!("Failed to read context");
                    return false;
               }
            } 
        }
        
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let mut addr = offset as u32;
        addr &= !0x3;
        if PRIORITY_BASE <= addr && addr < ENABLE_BASE {
            if self.priority_write(addr, data).is_err() {
                error!("Failed to write priority register");
                return false;
            }
        }
        else if ENABLE_BASE <= addr && addr < CONTEXT_BASE {
            let cntx:u32 = (addr - ENABLE_BASE) / ENABLE_PER_HART;
            addr -= cntx * ENABLE_PER_HART + ENABLE_BASE;
            if cntx < self.num_context {
                if self.context_enable_write(self.contexts.get(cntx as usize).unwrap(), addr, data).is_err() {
                    error!("Failed to write enable register");
                    return false;
                }
            } 
        }
        else if CONTEXT_BASE <= addr && addr < REG_SIZE {
            let cntx:u32 = (addr - CONTEXT_BASE) / CONTEXT_PER_HART;
            addr -= cntx * CONTEXT_PER_HART + CONTEXT_BASE;
            if cntx < self.num_context {
                if self.context_write(self.contexts.get(cntx as usize).unwrap(), addr, data).is_err() {
                    error!("Failed to write context");
                    return false;
                }
            } 
        }
        true
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.res)
    }

    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::Plic
    }
}

