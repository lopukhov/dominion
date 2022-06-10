// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::binutils::*;
use crate::CorruptedPackageError;
use crate::NotImplementedError;
use crate::ParseError;
use std::fmt;
use std::str;

pub(crate) const MAX_JUMPS: u8 = 5;

pub(crate) const MAX_LABEL_SIZE: usize = 63;
pub(crate) const MAX_NAME_SIZE: usize = 255;

const INIT_CAP: usize = 32;

#[derive(Clone, Debug)]
pub struct Name(String);

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Name {
    pub(crate) fn parse(packet: &[u8], start: usize) -> Result<(Self, usize), ParseError> {
        let mut s = String::with_capacity(INIT_CAP);
        let n = parse_with_jumps(&mut s, packet, start)?;
        if s.len() < MAX_NAME_SIZE {
            Ok((Name(s), n))
        } else {
            Err(CorruptedPackageError::NameLength(s.len()))?
        }
    }
}

fn parse_with_jumps(s: &mut String, packet: &[u8], mut pos: usize) -> Result<usize, ParseError> {
    let (mut size, mut jumps) = (0, 0);
    loop {
        if jumps > MAX_JUMPS {
            Err(CorruptedPackageError::ExcesiveJumps(jumps))?;
        }
        match read_label_metadata(packet, pos)? {
            LabelMeta::Pointer(ptr) if ptr >= pos => Err(CorruptedPackageError::InvalidJump)?,
            LabelMeta::Size(_) if jumps == 0 => {
                let walked = parse_no_jumps(s, &packet[pos..])?;
                (pos, size) = (pos + walked, walked);
            }
            LabelMeta::Size(_) => {
                let walked = parse_no_jumps(s, &packet[pos..])?;
                pos += walked;
            }
            LabelMeta::Pointer(ptr) if jumps == 0 => {
                (pos, size, jumps) = (ptr, size + 2, jumps + 1);
            }
            LabelMeta::Pointer(ptr) => (pos, jumps) = (ptr, jumps + 1),
            LabelMeta::End if jumps == 0 => return Ok(size + 1),
            LabelMeta::End => return Ok(size),
        }
    }
}

fn parse_no_jumps(s: &mut String, buff: &[u8]) -> Result<usize, ParseError> {
    let mut walked = 0;
    loop {
        match read_label_metadata(buff, walked)? {
            LabelMeta::Size(b) if b > MAX_LABEL_SIZE => Err(CorruptedPackageError::LabelLength(b))?,
            LabelMeta::Size(b) if buff.len() <= walked + b => {
                Err(CorruptedPackageError::LabelLength(b))?
            }
            LabelMeta::Size(b) => {
                let i = walked + 1;
                walked += b + 1;
                let label =
                    str::from_utf8(&buff[i..walked]).map_err(CorruptedPackageError::from)?;
                s.push_str(label);
                s.push('.');
            }
            LabelMeta::Pointer(_) => return Ok(walked),
            LabelMeta::End => return Ok(walked),
        }
    }
}

enum LabelMeta {
    End,
    // Although it is really an u8 because it is used for indexing we give an usize
    Size(usize),
    // Although it is really an u16 because it is used for indexing we give an usize
    Pointer(usize),
}

fn read_label_metadata(buff: &[u8], pos: usize) -> Result<LabelMeta, ParseError> {
    let b = safe_u8_read(buff, pos)?;
    match b {
        0 => Ok(LabelMeta::End),
        1..=0b0011_1111 => Ok(LabelMeta::Size(b as _)),
        0b1100_0000..=0xFF => Ok(LabelMeta::Pointer(
            (safe_u16_read(buff, pos)? ^ 0b1100_0000_0000_0000) as _,
        )),
        _ => Err(NotImplementedError::LabelPrefix(b))?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_jumps_easy() {
        let buff = [
            5, 104, 101, 108, 108, 111, 5, 119, 111, 114, 108, 100, 3, 99, 111, 109, 0, 1, 0, 0,
        ];
        let mut s = String::with_capacity(16);
        let n = parse_no_jumps(&mut s, &buff[..]).unwrap();
        assert_eq!(n, 16);
        assert_eq!(s, "hello.world.com.".to_string())
    }

    #[test]
    fn no_jumps_hard() {
        let buff = [
            5, 104, 101, 108, 108, 111, 5, 119, 111, 114, 108, 100, 3, 99, 111, 109, 0, 1, 0, 0,
        ];
        let mut s = String::with_capacity(16);
        let n = parse_with_jumps(&mut s, &buff[..], 0).unwrap();
        assert_eq!(n, 17);
        assert_eq!(s, "hello.world.com.".to_string())
    }

    #[test]
    fn with_jumps_hard() {
        let buff = [
            5, 119, 111, 114, 108, 100, 3, 99, 111, 109, 0, 1, 1, 1, 5, 104, 101, 108, 108, 111,
            192, 0, 1, 1, 1, 1, 1, 1,
        ];
        let mut s = String::with_capacity(14);
        let n = parse_with_jumps(&mut s, &buff[..], 14).unwrap();
        assert_eq!(n, 8);
        assert_eq!(s, "hello.world.com.".to_string())
    }
    #[test]
    fn not_allow_forward_jump() {
        let buff = [
            5, 104, 101, 108, 108, 111, 192, 10, 1, 0, 5, 119, 111, 114, 108, 100, 3, 99, 111, 109,
            0, 0, 0, 0,
        ];
        let mut s = String::with_capacity(16);
        match parse_with_jumps(&mut s, &buff[..], 0) {
            Ok(_) => panic!("Buffer with forward jump has been allowed"),
            Err(ParseError::CorruptPackage(e)) => assert_eq!(e, CorruptedPackageError::InvalidJump),
            _ => panic!("Did not give back appropiate error"),
        }
    }
}
