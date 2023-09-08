// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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
// - Modify virtio mmio for risc-v architecture
//
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::VirtioError;
use address_space::{AddressRange, AddressSpace, GuestAddress, RegionIoEventFd};
use byteorder::{ByteOrder, LittleEndian};
use devices::InterruptController;
use log::{error, warn};
#[cfg(target_arch = "x86_64")]
use machine_manager::config::{BootSource, Param};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use sysbus::{SysBus, SysBusDevOps, SysBusDevType, SysRes};
use util::byte_code::ByteCode;
use vmm_sys_util::eventfd::EventFd;

use super::{
    virtio_has_feature, Queue, QueueConfig, VirtioDevice, VirtioInterrupt, VirtioInterruptType,
    CONFIG_STATUS_ACKNOWLEDGE, CONFIG_STATUS_DRIVER, CONFIG_STATUS_DRIVER_OK, CONFIG_STATUS_FAILED,
    CONFIG_STATUS_FEATURES_OK, CONFIG_STATUS_NEEDS_RESET, NOTIFY_REG_OFFSET,
    QUEUE_TYPE_PACKED_VRING, QUEUE_TYPE_SPLIT_VRING, VIRTIO_F_RING_PACKED, VIRTIO_MMIO_INT_CONFIG,
    VIRTIO_MMIO_INT_VRING,
};
use anyhow::{anyhow, bail, Context, Result};

/// Registers of virtio-mmio device refer to Virtio Spec.
/// Magic value - Read Only.
const MAGIC_VALUE_REG: u64 = 0x00;
/// Virtio device version - Read Only.
const VERSION_REG: u64 = 0x04;
/// Virtio device ID - Read Only.
const DEVICE_ID_REG: u64 = 0x08;
/// Virtio vendor ID - Read Only.
const VENDOR_ID_REG: u64 = 0x0c;
/// Bitmask of the features supported by the device(host) (32 bits per set) - Read Only.
const DEVICE_FEATURES_REG: u64 = 0x10;
/// Device (host) features set selector - Write Only.
const DEVICE_FEATURES_SEL_REG: u64 = 0x14;
/// Bitmask of features activated by the driver (guest) (32 bits per set) - Write Only.
const DRIVER_FEATURES_REG: u64 = 0x20;
/// Activated features set selector - Write Only.
const DRIVER_FEATURES_SEL_REG: u64 = 0x24;
/// Queue selector - Write Only.
const QUEUE_SEL_REG: u64 = 0x30;
/// Maximum size of the currently selected queue - Read Only.
const QUEUE_NUM_MAX_REG: u64 = 0x34;
/// Queue size for the currently selected queue - Write Only.
const QUEUE_NUM_REG: u64 = 0x38;
/// Ready bit for the currently selected queue - Read Write.
const QUEUE_READY_REG: u64 = 0x44;
/// Interrupt status - Read Only.
const INTERRUPT_STATUS_REG: u64 = 0x60;
/// Interrupt acknowledge - Write Only.
const INTERRUPT_ACK_REG: u64 = 0x64;
/// Device status register - Read Write.
const STATUS_REG: u64 = 0x70;
/// The low 32bit of queue's Descriptor Table address.
const QUEUE_DESC_LOW_REG: u64 = 0x80;
/// The high 32bit of queue's Descriptor Table address.
const QUEUE_DESC_HIGH_REG: u64 = 0x84;
/// The low 32 bit of queue's Available Ring address.
const QUEUE_AVAIL_LOW_REG: u64 = 0x90;
/// The high 32 bit of queue's Available Ring address.
const QUEUE_AVAIL_HIGH_REG: u64 = 0x94;
/// The low 32bit of queue's Used Ring address.
const QUEUE_USED_LOW_REG: u64 = 0xa0;
/// The high 32bit of queue's Used Ring address.
const QUEUE_USED_HIGH_REG: u64 = 0xa4;
/// Configuration atomicity value.
const CONFIG_GENERATION_REG: u64 = 0xfc;

const VENDOR_ID: u32 = 0;
const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
const MMIO_VERSION: u32 = 2;

/// The maximum of virtio queue within a virtio device.
const MAXIMUM_NR_QUEUES: usize = 8;

/// HostNotifyInfo includes the info needed for notifying backend from guest.
pub struct HostNotifyInfo {
    /// Eventfds which notify backend to use the avail ring.
    events: Vec<Arc<EventFd>>,
}

impl HostNotifyInfo {
    pub fn new(queue_num: usize) -> Self {
        let mut events = Vec::new();
        for _i in 0..queue_num {
            events.push(Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()));
        }

        HostNotifyInfo { events }
    }
}

/// The state of virtio-mmio device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct VirtioMmioState {
    /// Identify if this device is activated by frontend driver.
    activated: bool,
    /// Config space of virtio mmio device.
    config_space: VirtioMmioCommonConfig,
}

/// The configuration of virtio-mmio device, the fields refer to Virtio Spec.
#[derive(Copy, Clone, Default)]
pub struct VirtioMmioCommonConfig {
    /// Bitmask of the features supported by the device (host)(32 bits per set).
    features_select: u32,
    /// Device (host) feature-setting selector.
    acked_features_select: u32,
    /// Interrupt status value.
    interrupt_status: u32,
    /// Device status.
    device_status: u32,
    /// Configuration atomicity value.
    config_generation: u32,
    /// Queue selector.
    queue_select: u32,
    /// The configuration of queues.
    queues_config: [QueueConfig; MAXIMUM_NR_QUEUES],
    /// The number of queues.
    queue_num: usize,
    /// The type of queue, either be split ring or packed ring.
    queue_type: u16,
}

impl VirtioMmioCommonConfig {
    pub fn new(device: &Arc<Mutex<dyn VirtioDevice>>) -> Self {
        let locked_device = device.lock().unwrap();
        let mut queues_config = [QueueConfig::default(); 8];
        let queue_size = locked_device.queue_size();
        let queue_num = locked_device.queue_num();
        for queue_config in queues_config.iter_mut().take(queue_num) {
            *queue_config = QueueConfig::new(queue_size);
        }

        VirtioMmioCommonConfig {
            queues_config,
            queue_num,
            queue_type: QUEUE_TYPE_SPLIT_VRING,
            ..Default::default()
        }
    }

    /// Check whether virtio device status is as expected.
    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    /// Get the status of virtio device
    fn get_device_status(&self) -> u32 {
        self.device_status
    }

    /// Get mutable QueueConfig structure of virtio device.
    fn get_mut_queue_config(&mut self) -> Result<&mut QueueConfig> {
        if self.check_device_status(
            CONFIG_STATUS_FEATURES_OK,
            CONFIG_STATUS_DRIVER_OK | CONFIG_STATUS_FAILED,
        ) {
            let queue_select = self.queue_select;
            self.queues_config
                .get_mut(queue_select as usize)
                .ok_or_else(|| {
                    anyhow!(
                        "Mmio-reg queue_select {} overflows for mutable queue config",
                        queue_select,
                    )
                })
        } else {
            Err(anyhow!(VirtioError::DevStatErr(self.device_status)))
        }
    }

    /// Get immutable QueueConfig structure of virtio device.
    fn get_queue_config(&self) -> Result<&QueueConfig> {
        let queue_select = self.queue_select;
        self.queues_config
            .get(queue_select as usize)
            .ok_or_else(|| {
                anyhow!(
                    "Mmio-reg queue_select overflows {} for immutable queue config",
                    queue_select,
                )
            })
    }

    /// Read data from the common config of virtio device.
    /// Return the config value in u32.
    /// # Arguments
    ///
    /// * `device` - Virtio device entity.
    /// * `offset` - The offset of common config.
    fn read_common_config(
        &mut self,
        device: &Arc<Mutex<dyn VirtioDevice>>,
        interrupt_status: &Arc<AtomicU32>,
        offset: u64,
    ) -> Result<u32> {
        let value = match offset {
            MAGIC_VALUE_REG => MMIO_MAGIC_VALUE,
            VERSION_REG => MMIO_VERSION,
            DEVICE_ID_REG => device.lock().unwrap().device_type(),
            VENDOR_ID_REG => VENDOR_ID,
            DEVICE_FEATURES_REG => {
                let mut features = device
                    .lock()
                    .unwrap()
                    .get_device_features(self.features_select);
                if self.features_select == 1 {
                    features |= 0x1; // enable support of VirtIO Version 1
                }
                features
            }
            QUEUE_NUM_MAX_REG => self
                .get_queue_config()
                .map(|config| u32::from(config.max_size))?,
            QUEUE_READY_REG => self.get_queue_config().map(|config| config.ready as u32)?,
            INTERRUPT_STATUS_REG => {
                self.interrupt_status = interrupt_status.load(Ordering::SeqCst);
                self.interrupt_status
            }
            STATUS_REG => self.device_status,
            CONFIG_GENERATION_REG => self.config_generation,
            _ => {
                return Err(anyhow!(VirtioError::MmioRegErr(offset)));
            }
        };

        Ok(value)
    }

    /// Write data to the common config of virtio device.
    ///
    /// # Arguments
    ///
    /// * `device` - Virtio device entity.
    /// * `offset` - The offset of common config.
    /// * `value` - The value to write.
    ///
    /// # Errors
    ///
    /// Returns Error if the offset is out of bound.
    fn write_common_config(
        &mut self,
        device: &Arc<Mutex<dyn VirtioDevice>>,
        interrupt_status: &Arc<AtomicU32>,
        offset: u64,
        value: u32,
    ) -> Result<()> {
        match offset {
            DEVICE_FEATURES_SEL_REG => self.features_select = value,
            DRIVER_FEATURES_REG => {
                if self.check_device_status(
                    CONFIG_STATUS_DRIVER,
                    CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_FAILED,
                ) {
                    device
                        .lock()
                        .unwrap()
                        .set_driver_features(self.acked_features_select, value);
                    if self.acked_features_select == 1
                        && virtio_has_feature(u64::from(value) << 32, VIRTIO_F_RING_PACKED)
                    {
                        self.queue_type = QUEUE_TYPE_PACKED_VRING;
                    }
                } else {
                    return Err(anyhow!(VirtioError::DevStatErr(self.device_status)));
                }
            }
            DRIVER_FEATURES_SEL_REG => self.acked_features_select = value,
            QUEUE_SEL_REG => self.queue_select = value,
            QUEUE_NUM_REG => self
                .get_mut_queue_config()
                .map(|config| config.size = value as u16)?,
            QUEUE_READY_REG => self
                .get_mut_queue_config()
                .map(|config| config.ready = value == 1)?,
            INTERRUPT_ACK_REG => {
                if self.check_device_status(CONFIG_STATUS_DRIVER_OK, 0) {
                    self.interrupt_status = interrupt_status.fetch_and(!value, Ordering::SeqCst);
                }
            }
            STATUS_REG => self.device_status = value,
            QUEUE_DESC_LOW_REG => self.get_mut_queue_config().map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | u64::from(value));
            })?,
            QUEUE_DESC_HIGH_REG => self.get_mut_queue_config().map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | (u64::from(value) << 32));
            })?,
            QUEUE_AVAIL_LOW_REG => self.get_mut_queue_config().map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | u64::from(value));
            })?,
            QUEUE_AVAIL_HIGH_REG => self.get_mut_queue_config().map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | (u64::from(value) << 32));
            })?,
            QUEUE_USED_LOW_REG => self.get_mut_queue_config().map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | u64::from(value));
            })?,
            QUEUE_USED_HIGH_REG => self.get_mut_queue_config().map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | (u64::from(value) << 32));
            })?,
            _ => {
                return Err(anyhow!(VirtioError::MmioRegErr(offset)));
            }
        };
        Ok(())
    }
}

/// virtio-mmio device structure.
pub struct VirtioMmioDevice {
    // The entity of low level device.
    pub device: Arc<Mutex<dyn VirtioDevice>>,
    // EventFd used to send interrupt to VM
    interrupt_evt: Arc<EventFd>,
    // Interrupt status.
    interrupt_status: Arc<AtomicU32>,
    // HostNotifyInfo used for guest notifier
    host_notify_info: HostNotifyInfo,
    // The state of virtio mmio device.
    state: Arc<Mutex<VirtioMmioState>>,
    // System address space.
    mem_space: Arc<AddressSpace>,
    // Virtio queues.
    queues: Vec<Arc<Mutex<Queue>>>,
    // System Resource of device.
    res: SysRes,
    /// The function for interrupt triggering.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    irq_chip: Arc<Mutex<InterruptController>>,
}

impl VirtioMmioDevice {
    pub fn new(mem_space: &Arc<AddressSpace>, device: Arc<Mutex<dyn VirtioDevice>>, irq_chip: Arc<Mutex<InterruptController>>) -> Self {
        let device_clone = device.clone();
        let queue_num = device_clone.lock().unwrap().queue_num();

        VirtioMmioDevice {
            device,
            interrupt_evt: Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
            interrupt_status: Arc::new(AtomicU32::new(0)),
            host_notify_info: HostNotifyInfo::new(queue_num),
            state: Arc::new(Mutex::new(VirtioMmioState {
                activated: false,
                config_space: VirtioMmioCommonConfig::new(&device_clone),
            })),
            mem_space: mem_space.clone(),
            queues: Vec::new(),
            res: SysRes::default(),
            interrupt_cb: None,
            irq_chip,
        }
    }

    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
        #[cfg(target_arch = "x86_64")] bs: &Arc<Mutex<BootSource>>,
    ) -> Result<Arc<Mutex<Self>>> {
        //self.assign_interrupt_cb();
        self.device
            .lock()
            .unwrap()
            .realize()
            .with_context(|| "Failed to realize virtio.")?;

        if region_base >= sysbus.mmio_region.1 {
            bail!("Mmio region space exhausted.");
        }
        self.set_sys_resource(sysbus, region_base, region_size)?;
        self.assign_interrupt_cb();
        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size)?;

        #[cfg(target_arch = "x86_64")]
        bs.lock().unwrap().kernel_cmdline.push(Param {
            param_type: "virtio_mmio.device".to_string(),
            value: format!(
                "{}@0x{:08x}:{}",
                region_size,
                region_base,
                dev.lock().unwrap().res.irq
            ),
        });
        Ok(dev)
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(&mut self) -> Result<()> {
        let mut locked_state = self.state.lock().unwrap();
        let queue_num = locked_state.config_space.queue_num;
        let queue_type = locked_state.config_space.queue_type;
        let queues_config = &mut locked_state.config_space.queues_config[0..queue_num];
        let cloned_mem_space = self.mem_space.clone();
        for q_config in queues_config.iter_mut() {
            q_config.addr_cache.desc_table_host = cloned_mem_space
                .get_host_address(q_config.desc_table)
                .unwrap_or(0);
            q_config.addr_cache.avail_ring_host = cloned_mem_space
                .get_host_address(q_config.avail_ring)
                .unwrap_or(0);
            q_config.addr_cache.used_ring_host = cloned_mem_space
                .get_host_address(q_config.used_ring)
                .unwrap_or(0);
            let queue = Queue::new(*q_config, queue_type)?;
            if !queue.is_valid(&self.mem_space) {
                bail!("Invalid queue");
            }
            self.queues.push(Arc::new(Mutex::new(queue)));
        }
        drop(locked_state);

        let mut queue_evts = Vec::<Arc<EventFd>>::new();
        for fd in self.host_notify_info.events.iter() {
            queue_evts.push(fd.clone());
        }

        let mut events = Vec::new();
        for _i in 0..self.device.lock().unwrap().queue_num() {
            events.push(Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()));
        }

        self.device.lock().unwrap().set_guest_notifiers(&events)?;

        if let Some(cb) = self.interrupt_cb.clone() {
            self.device.lock().unwrap().activate(
                self.mem_space.clone(),
                cb,
                &self.queues,
                queue_evts,
            )?;
        } else {
            bail!("Failed to activate device: No interrupt callback");
        }

        Ok(())
    }

    fn assign_interrupt_cb(&mut self) {
        let interrupt_status = self.interrupt_status.clone();
        let interrupt_evt = self.interrupt_evt.clone();
        let cloned_state = self.state.clone();
        let irq_chip = self.irq_chip.clone();
        let irq = self.get_sys_resource().unwrap().irq as u8;
        let cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, _queue: Option<&Queue>, needs_reset: bool| {
                let status = match int_type {
                    VirtioInterruptType::Config => {
                        let mut locked_state = cloned_state.lock().unwrap();
                        if needs_reset {
                            locked_state.config_space.device_status |= CONFIG_STATUS_NEEDS_RESET;
                            if locked_state.config_space.device_status & CONFIG_STATUS_DRIVER_OK
                                == 0
                            {
                                return Ok(());
                            }
                        }
                        locked_state.config_space.config_generation += 1;
                        // Use (CONFIG | VRING) instead of CONFIG, it can be used to solve the
                        // IO stuck problem by change the device configure.
                        VIRTIO_MMIO_INT_CONFIG | VIRTIO_MMIO_INT_VRING
                    }
                    VirtioInterruptType::Vring => VIRTIO_MMIO_INT_VRING,
                };
                interrupt_status.fetch_or(status, Ordering::SeqCst);
                interrupt_evt
                    .write(1)
                    .with_context(|| anyhow!(VirtioError::EventFdWrite))?;
                irq_chip.lock().unwrap().kvm_irq_trigger(irq);
                Ok(())
            },
        ) as VirtioInterrupt);

        self.interrupt_cb = Some(cb);
    }
}

impl SysBusDevOps for VirtioMmioDevice {
    /// Read data by virtio driver from VM.
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let value = match self.state.lock().unwrap().config_space.read_common_config(
                    &self.device,
                    &self.interrupt_status,
                    offset,
                ) {
                    Ok(v) => v,
                    Err(ref e) => {
                        error!(
                            "Failed to read mmio register {}, type: {}, {:?}",
                            offset,
                            self.device.lock().unwrap().device_type(),
                            e,
                        );
                        return false;
                    }
                };
                LittleEndian::write_u32(data, value);
            }
            0x100..=0xfff => {
                if let Err(ref e) = self
                    .device
                    .lock()
                    .unwrap()
                    .read_config(offset - 0x100, data)
                {
                    error!(
                        "Failed to read virtio-dev config space {} type: {} {:?}",
                        offset - 0x100,
                        self.device.lock().unwrap().device_type(),
                        e,
                    );
                    return false;
                }
            }
            _ => {
                warn!(
                    "Failed to read mmio register: overflows, offset is 0x{:x}, type: {}",
                    offset,
                    self.device.lock().unwrap().device_type(),
                );
            }
        };
        true
    }

    /// Write data by virtio driver from VM.
    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let mut locked_state = self.state.lock().unwrap();
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let value = LittleEndian::read_u32(data);
                if let Err(ref e) = locked_state.config_space.write_common_config(
                    &self.device,
                    &self.interrupt_status,
                    offset,
                    value,
                ) {
                    error!(
                        "Failed to write mmio register {}, type: {}, {:?}",
                        offset,
                        self.device.lock().unwrap().device_type(),
                        e,
                    );
                    return false;
                }

                if locked_state.config_space.check_device_status(
                    CONFIG_STATUS_ACKNOWLEDGE
                        | CONFIG_STATUS_DRIVER
                        | CONFIG_STATUS_DRIVER_OK
                        | CONFIG_STATUS_FEATURES_OK,
                    CONFIG_STATUS_FAILED,
                ) && !locked_state.activated
                {
                    drop(locked_state);
                    if let Err(ref e) = self.activate() {
                        error!(
                            "Failed to activate dev, type: {}, {:?}",
                            self.device.lock().unwrap().device_type(),
                            e,
                        );
                        return false;
                    }
                    self.state.lock().unwrap().activated = true;
                }
            }
            0x100..=0xfff => {
                if locked_state
                    .config_space
                    .check_device_status(CONFIG_STATUS_DRIVER, CONFIG_STATUS_FAILED)
                {
                    if let Err(ref e) = self
                        .device
                        .lock()
                        .unwrap()
                        .write_config(offset - 0x100, data)
                    {
                        error!(
                            "Failed to write virtio-dev config space {}, type: {}, {:?}",
                            offset - 0x100,
                            self.device.lock().unwrap().device_type(),
                            e,
                        );
                        return false;
                    }
                } else {
                    error!("Failed to write virtio-dev config space: driver is not ready 0x{:X}, type: {}",
                        locked_state.config_space.get_device_status(),
                        self.device.lock().unwrap().device_type(),
                    );
                    return false;
                }
            }
            _ => {
                warn!(
                    "Failed to write mmio register: overflows, offset is 0x{:x} type: {}",
                    offset,
                    self.device.lock().unwrap().device_type(),
                );
                return false;
            }
        }
        true
    }

    fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
        let mut ret = Vec::new();
        for (index, eventfd) in self.host_notify_info.events.iter().enumerate() {
            let addr = u64::from(NOTIFY_REG_OFFSET);
            ret.push(RegionIoEventFd {
                fd: eventfd.clone(),
                addr_range: AddressRange::from((addr, std::mem::size_of::<u32>() as u64)),
                data_match: true,
                data: index as u64,
            })
        }
        ret
    }

    fn interrupt_evt(&self) -> Option<&EventFd> {
        Some(self.interrupt_evt.as_ref())
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.res)
    }

    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::VirtioMmio
    }
}


impl StateTransfer for VirtioMmioDevice {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        let mut state = self.state.lock().unwrap();

        for (index, queue) in self.queues.iter().enumerate() {
            state.config_space.queues_config[index] =
                queue.lock().unwrap().vring.get_queue_config();
        }
        state.config_space.interrupt_status = self.interrupt_status.load(Ordering::Relaxed);

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::Result<()> {
        let s_len = std::mem::size_of::<VirtioMmioState>();
        if state.len() != s_len {
            bail!("Invalid state length {}, expected {}", state.len(), s_len);
        }
        let mut locked_state = self.state.lock().unwrap();
        locked_state.as_mut_bytes().copy_from_slice(state);
        let cloned_mem_space = self.mem_space.clone();
        let mut queue_states = locked_state.config_space.queues_config
            [0..locked_state.config_space.queue_num]
            .to_vec();
        self.queues = queue_states
            .iter_mut()
            .map(|queue_state| {
                queue_state.addr_cache.desc_table_host = cloned_mem_space
                    .get_host_address(queue_state.desc_table)
                    .unwrap_or(0);
                queue_state.addr_cache.avail_ring_host = cloned_mem_space
                    .get_host_address(queue_state.avail_ring)
                    .unwrap_or(0);
                queue_state.addr_cache.used_ring_host = cloned_mem_space
                    .get_host_address(queue_state.used_ring)
                    .unwrap_or(0);
                Arc::new(Mutex::new(
                    Queue::new(*queue_state, locked_state.config_space.queue_type).unwrap(),
                ))
            })
            .collect();
        self.interrupt_status
            .store(locked_state.config_space.interrupt_status, Ordering::SeqCst);

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        if let Some(alias) = MigrationManager::get_desc_alias(&VirtioMmioState::descriptor().name) {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for VirtioMmioDevice {
    fn resume(&mut self) -> migration::Result<()> {
        if self.state.lock().unwrap().activated {
            let mut queue_evts = Vec::<Arc<EventFd>>::new();
            for fd in self.host_notify_info.events.iter() {
                queue_evts.push(fd.clone());
            }

            if let Some(cb) = self.interrupt_cb.clone() {
                if let Err(e) = self.device.lock().unwrap().activate(
                    self.mem_space.clone(),
                    cb,
                    &self.queues,
                    queue_evts,
                ) {
                    bail!("Failed to resume virtio mmio device: {}", e);
                }
            } else {
                bail!("Failed to resume device: No interrupt callback");
            }
        }

        Ok(())
    }
}

