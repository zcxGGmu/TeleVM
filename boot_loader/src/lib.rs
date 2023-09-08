// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
//
// Copyright (c) 2023 China Telecom Co.,Ltd. All rights reserved.
// 
// Modifications made by China Telecom Co.,Ltd:
// - Modify bootloader for risc-v architecture
//
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

pub mod error;
#[allow(clippy::upper_case_acronyms)]
#[cfg(target_arch = "riscv64")]
pub mod riscv;

#[cfg(target_arch = "riscv64")]
pub use riscv::load_linux;
#[cfg(target_arch = "riscv64")]
pub use riscv::RISCVBootLoader as BootLoader;
#[cfg(target_arch = "riscv64")]
pub use riscv::RISCVBootLoaderConfig as BootLoaderConfig;
