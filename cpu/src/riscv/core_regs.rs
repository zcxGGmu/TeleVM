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

use std::mem::size_of;

use kvm_bindings::{
    kvm_riscv_config, kvm_riscv_core, kvm_riscv_timer, user_regs_struct, KVM_REG_RISCV,
    KVM_REG_RISCV_CONFIG, KVM_REG_RISCV_CORE, KVM_REG_RISCV_TIMER, KVM_REG_SIZE_U64,
};
use kvm_ioctls::VcpuFd;
use util::offset_of;
use vmm_sys_util::errno;

pub type Result<T> = std::result::Result<T, errno::Error>;

/// RISCV cpu config register.
/// See: https://elixir.bootlin.com/linux/v6.0/source/arch/riscv/include/uapi/asm/kvm.h#L49
pub enum RISCVConfigRegs {
    ISA,
}

impl Into<u64> for RISCVConfigRegs {
    fn into(self) -> u64 {
        let reg_offset = match self {
            RISCVConfigRegs::ISA => {
                offset_of!(kvm_riscv_config, isa)
            }
        };
        // calculate reg_id
        KVM_REG_RISCV as u64
        | KVM_REG_SIZE_U64 as u64
        | u64::from(KVM_REG_RISCV_CONFIG)
        | (reg_offset / size_of::<u64>()) as u64
    }
}

/// RISCV cpu core register.
/// See: https://elixir.bootlin.com/linux/v6.0/source/arch/riscv/include/uapi/asm/kvm.h#L54
/// User-mode register state for core dumps, ptrace, sigcontext
/// See: https://elixir.bootlin.com/linux/v6.0/source/arch/riscv/include/uapi/asm/ptrace.h#L19
#[allow(dead_code)]
pub enum RISCVCoreRegs {
    PC,
    RA,
    SP,
    GP,
    TP,
    T0,
    T1,
    T2,
    S0,
    S1,
    A0,
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,
    T4,
    T5,
    T6,
    MODE,
}

impl Into<u64> for RISCVCoreRegs {
    fn into(self) -> u64 {
        let reg_offset = match self {
            RISCVCoreRegs::PC => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, pc)
            }
            RISCVCoreRegs::RA => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, ra)
            }
            RISCVCoreRegs::SP => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, sp)
            }
            RISCVCoreRegs::GP => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, gp)
            }
            RISCVCoreRegs::TP => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, tp)
            }
            RISCVCoreRegs::T0 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, t0)
            }
            RISCVCoreRegs::T1 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, t1)
            }
            RISCVCoreRegs::T2 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, t2)
            }
            RISCVCoreRegs::S0 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s0)
            }
            RISCVCoreRegs::S1 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s1)
            }
            RISCVCoreRegs::A0 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, a0)
            }
            RISCVCoreRegs::A1 => { 
                offset_of!(kvm_riscv_core, regs, user_regs_struct, a1)
            }
            RISCVCoreRegs::A2 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, a2)
            }
            RISCVCoreRegs::A3 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, a3)
            }
            RISCVCoreRegs::A4 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, a4)
            }
            RISCVCoreRegs::A5 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, a5)
            }
            RISCVCoreRegs::A6 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, a6)
            }
            RISCVCoreRegs::A7 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, a7)
            }
            RISCVCoreRegs::S2 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s2)
            }
            RISCVCoreRegs::S3 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s3)
            }
            RISCVCoreRegs::S4 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s4)
            }
            RISCVCoreRegs::S5 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s5)
            }
            RISCVCoreRegs::S6 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s6)
            }
            RISCVCoreRegs::S7 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s7)
            }
            RISCVCoreRegs::S8 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s8)
            }
            RISCVCoreRegs::S9 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s9)
            }
            RISCVCoreRegs::S10 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s10)
            }
            RISCVCoreRegs::S11 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, s11)
            }
            RISCVCoreRegs::T3 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, t3)
            }
            RISCVCoreRegs::T4 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, t4)
            }
            RISCVCoreRegs::T5 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, t5)
            }
            RISCVCoreRegs::T6 => {
                offset_of!(kvm_riscv_core, regs, user_regs_struct, t6)
            }
            RISCVCoreRegs::MODE => {
                offset_of!(kvm_riscv_core, mode)
            }
        };

        // The core registers of an riscv machine are represented
        // in kernel by the `kvm_riscv_core` structure.

        // struct kvm_riscv_core {
        //     struct user_regs_struct regs;
        //     unsigned long mode;
        // };

        // struct user_regs_struct {
        //     unsigned long pc;
        //     unsigned long ra;
        //     unsigned long sp;
        //     unsigned long gp;
        //     unsigned long tp;
        //     unsigned long t0;
        //     unsigned long t1;
        //     unsigned long t2;
        //     unsigned long s0;
        //     unsigned long s1;
        //     unsigned long a0;
        //     unsigned long a1;
        //      .....
        //     };

        // #define KVM_REG_RISCV	0x8000000000000000ULL
        // #define KVM_REG_RISCV_TYPE_SHIFT 24
        // #define KVM_REG_RISCV_CORE	(0x02 << KVM_REG_RISCV_TYPE_SHIFT)
        // #define KVM_REG_RISCV_CSR	(0x03 << KVM_REG_RISCV_TYPE_SHIFT)
        // #define KVM_REG_RISCV_TIMER		(0x04 << KVM_REG_RISCV_TYPE_SHIFT)
        // #define KVM_REG_RISCV_FP_F		(0x05 << KVM_REG_RISCV_TYPE_SHIFT)
        // #define KVM_REG_RISCV_FP_D		(0x06 << KVM_REG_RISCV_TYPE_SHIFT)
        // #define KVM_REG_RISCV_ISA_EXT		(0x07 << KVM_REG_RISCV_TYPE_SHIFT)

        // The id of the register is encoded as specified for `KVM_GET_ONE_REG` in the kernel documentation.
        // reg_id = KVM_REG_RISCV | KVM_REG_SIZE_* | KVM_REG_RISCV_* | reg_offset_index
        // See: https://elixir.bootlin.com/linux/v6.0/source/arch/riscv/include/uapi/asm/kvm.h#L122
        // reg_offset_index = reg_offset / sizeof(unsigned long)
        // KVM_REG_RISCV_* => KVM_REG_RISCV_CORE/KVM_REG_RISCV_CSR/KVM_REG_RISCV_TIMER/....
        // KVM_REG_SIZE_* => KVM_REG_SIZE_U32/KVM_REG_SIZE_U64

        // calculate reg_id
        KVM_REG_RISCV as u64
            | KVM_REG_SIZE_U64 as u64
            | u64::from(KVM_REG_RISCV_CORE)
            | (reg_offset / size_of::<u64>()) as u64
    }
}

/// RISCV cpu time register.
/// See: https://elixir.bootlin.com/linux/v6.0/source/arch/riscv/include/uapi/asm/kvm.h#L78
pub enum RISCVTimerRegs {
    FREQUENCY,
    TIME,
    COMPARE,
    STATE,
}

impl Into<u64> for RISCVTimerRegs {
    fn into(self) -> u64 {
        let reg_offset = match self {
            RISCVTimerRegs::FREQUENCY => {
                offset_of!(kvm_riscv_timer, frequency)
            }
            RISCVTimerRegs::TIME => {
                offset_of!(kvm_riscv_timer, time)
            }
            RISCVTimerRegs::COMPARE => {
                offset_of!(kvm_riscv_timer, compare)
            }
            RISCVTimerRegs::STATE => {
                offset_of!(kvm_riscv_timer, state)
            }
        };

        // calculate reg_id
        KVM_REG_RISCV as u64
            | KVM_REG_SIZE_U64 as u64
            | u64::from(KVM_REG_RISCV_TIMER)
            | (reg_offset / size_of::<u64>()) as u64
    }
}

/// Returns the vcpu's current `config_register`.
///
/// The register state is gotten from `KVM_GET_ONE_REG` api in KVM.
///
/// # Arguments
///
/// * `vcpu_fd` - the VcpuFd in KVM mod.
pub fn get_config_regs(vcpu_fd: &VcpuFd) -> Result<kvm_riscv_config> {
    let mut config_regs = kvm_riscv_config::default();
    let isa = vcpu_fd.get_one_reg(RISCVConfigRegs::ISA.into())?;
    config_regs.isa = isa as u64;

    Ok(config_regs)
}

/// Sets the vcpu's current "core_register"
///
/// The register state is gotten from `KVM_SET_ONE_REG` api in KVM.
///
/// # Arguments
///
/// * `vcpu_fd` - the VcpuFd in KVM mod.
/// * `core_regs` - kvm_regs state to be written.
pub fn set_core_regs(vcpu_fd: &VcpuFd, core_regs: kvm_riscv_core) -> Result<()> {
    vcpu_fd.set_one_reg(RISCVCoreRegs::PC.into(), core_regs.regs.pc as u128)?;
    vcpu_fd.set_one_reg(RISCVCoreRegs::A0.into(), core_regs.regs.a0 as u128)?;
    vcpu_fd.set_one_reg(RISCVCoreRegs::A1.into(), core_regs.regs.a1 as u128)?;

    Ok(())
}

/// Returns the vcpu's current `timer_register`.
///
/// The register state is gotten from `KVM_GET_ONE_REG` api in KVM.
///
/// # Arguments
///
/// * `vcpu_fd` - the VcpuFd in KVM mod.
pub fn get_timer_regs(vcpu_fd: &VcpuFd) -> Result<kvm_riscv_timer> {
    let mut timer_regs = kvm_riscv_timer::default();
    let frequency = vcpu_fd.get_one_reg(RISCVTimerRegs::FREQUENCY.into())?;
    timer_regs.frequency = frequency as u64;
    let time = vcpu_fd.get_one_reg(RISCVTimerRegs::TIME.into())?;
    timer_regs.time = time as u64;
    let compare = vcpu_fd.get_one_reg(RISCVTimerRegs::COMPARE.into())?;
    timer_regs.compare = compare as u64;
    let state = vcpu_fd.get_one_reg(RISCVTimerRegs::STATE.into())?;
    timer_regs.state = state as u64;

    Ok(timer_regs)
}
