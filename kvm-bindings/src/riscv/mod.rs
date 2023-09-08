// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(clippy::all)]
// Keep this until https://github.com/rust-lang/rust-bindgen/issues/1651 is fixed.
#[cfg_attr(test, allow(deref_nullptr))]
pub mod bindings;

pub use self::bindings::*;
