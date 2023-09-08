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

use kvm_ioctls::{Cap, Kvm};

// Capabilities for RISCV cpu.
#[derive(Debug, Clone)]
pub struct RISCVCPUCaps {
    pub ioevent_fd: bool,
    pub user_mem: bool,
    pub mp_state: bool,
    pub one_reg: bool,
}

impl RISCVCPUCaps {
    /// Initialize RISCVCPUCaps instance.
    pub fn init_capabilities() -> Self {
        let kvm = Kvm::new().unwrap();

        RISCVCPUCaps {
            ioevent_fd: kvm.check_extension(Cap::Ioeventfd),
            user_mem: kvm.check_extension(Cap::UserMemory),
            mp_state: kvm.check_extension(Cap::MpState),
            one_reg: kvm.check_extension(Cap::OneReg),
        }
    }
}
