// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::CorruptedPackageError;
use std::net::Ipv4Addr;

#[inline]
fn safe_read<const N: usize>(buff: &[u8], pos: usize) -> Result<[u8; N], CorruptedPackageError> {
    let mut bytes = [0u8; N];
    match buff.get(pos..pos + N) {
        Some(buff) => {
            bytes.copy_from_slice(buff);
            Ok(bytes)
        }
        None => Err(CorruptedPackageError::OobRead(pos)),
    }
}

#[inline]
pub(crate) fn safe_u8_read(buff: &[u8], pos: usize) -> Result<u8, CorruptedPackageError> {
    buff.get(pos)
        .ok_or(CorruptedPackageError::OobRead(pos))
        .map(|n| *n)
}

#[inline]
pub(crate) fn safe_u16_read(buff: &[u8], pos: usize) -> Result<u16, CorruptedPackageError> {
    let bytes = safe_read::<2>(buff, pos)?;
    Ok(u16::from_be_bytes(bytes))
}

#[inline]
pub(crate) fn safe_i32_read(buff: &[u8], pos: usize) -> Result<i32, CorruptedPackageError> {
    let bytes = safe_read::<4>(buff, pos)?;
    Ok(i32::from_be_bytes(bytes))
}

#[inline]
pub(crate) fn safe_ipv4_read(buff: &[u8], pos: usize) -> Result<Ipv4Addr, CorruptedPackageError> {
    let bytes = safe_read::<4>(buff, pos)?;
    Ok(Ipv4Addr::from(bytes))
}

#[inline]
pub(crate) fn push_u16(target: &mut Vec<u8>, n: u16) {
    target.extend(n.to_be_bytes());
}

#[inline]
pub(crate) fn push_i32(target: &mut Vec<u8>, n: i32) {
    target.extend(n.to_be_bytes());
}
