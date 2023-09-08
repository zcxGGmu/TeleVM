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

use super::Iovec;
use libc::{c_int, c_void, fdatasync, iovec, off_t, pread, preadv, pwrite, pwritev, size_t};
use log::error;
use std::os::unix::io::RawFd;

pub fn raw_read(fd: RawFd, buf: u64, size: usize, offset: usize) -> i64 {
    let mut ret;
    loop {
        // SAFETY: fd and buf is valid.
        ret = unsafe {
            pread(
                fd as c_int,
                buf as *mut c_void,
                size as size_t,
                offset as off_t,
            ) as i64
        };
        if !(ret < 0 && (errno::errno().0 == libc::EINTR || errno::errno().0 == libc::EAGAIN)) {
            break;
        }
    }
    if ret < 0 {
        error!(
            "Failed to pread: buf{}, size{}, offset{}, errno{}.",
            buf,
            size,
            offset,
            errno::errno().0
        );
    }
    ret
}

pub fn raw_readv(fd: RawFd, iovec: &[Iovec], offset: usize) -> i64 {
    let mut ret;
    loop {
        // SAFETY: fd and buf is valid.
        ret = unsafe {
            preadv(
                fd as c_int,
                iovec.as_ptr() as *const iovec,
                iovec.len() as c_int,
                offset as off_t,
            ) as i64
        };
        if !(ret < 0 && (errno::errno().0 == libc::EINTR || errno::errno().0 == libc::EAGAIN)) {
            break;
        }
    }
    if ret < 0 {
        error!(
            "Failed to preadv: offset{}, errno{}.",
            offset,
            errno::errno().0,
        );
    }
    ret
}

pub fn raw_write(fd: RawFd, buf: u64, size: usize, offset: usize) -> i64 {
    let mut ret;
    loop {
        // SAFETY: fd and buf is valid.
        ret = unsafe {
            pwrite(
                fd as c_int,
                buf as *mut c_void,
                size as size_t,
                offset as off_t,
            ) as i64
        };
        if !(ret < 0 && (errno::errno().0 == libc::EINTR || errno::errno().0 == libc::EAGAIN)) {
            break;
        }
    }
    if ret < 0 {
        error!(
            "Failed to pwrite: buf{}, size{}, offset{}, errno{}.",
            buf,
            size,
            offset,
            errno::errno().0,
        );
    }
    ret
}

pub fn raw_writev(fd: RawFd, iovec: &[Iovec], offset: usize) -> i64 {
    let mut ret;
    loop {
        // SAFETY: fd and buf is valid.
        ret = unsafe {
            pwritev(
                fd as c_int,
                iovec.as_ptr() as *const iovec,
                iovec.len() as c_int,
                offset as off_t,
            ) as i64
        };
        if !(ret < 0 && (errno::errno().0 == libc::EINTR || errno::errno().0 == libc::EAGAIN)) {
            break;
        }
    }
    if ret < 0 {
        error!(
            "Failed to pwritev: offset{}, errno{}.",
            offset,
            errno::errno().0,
        );
    }
    ret
}

pub fn raw_datasync(fd: RawFd) -> i64 {
    // SAFETY: fd is valid.
    let ret = unsafe { i64::from(fdatasync(fd)) };
    if ret < 0 {
        error!("Failed to fdatasync: errno{}.", errno::errno().0);
    }
    ret
}
