//! # Legacy
//!
//! This mod emulate legacy devices include RTC and Serial.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. Pl031 device, Arm PrimeCell Real Time Clock.
//! 2. Serial device, Serial UART.
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`

mod chardev;
pub mod error;
#[allow(dead_code)]
mod fwcfg;
mod serial;
pub use anyhow::Result;
pub use chardev::{Chardev, InputReceiver};
pub use error::LegacyError;
pub use fwcfg::FwCfgMem;
pub use fwcfg::{FwCfgEntryType, FwCfgOps};
pub use serial::{Serial, SERIAL_ADDR};
