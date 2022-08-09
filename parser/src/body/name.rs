// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::binutils::*;
use crate::ParseError;

use thiserror::Error;

use std::fmt;
use std::iter::zip;
use std::iter::Copied;
use std::iter::Rev;
use std::str;

const INIT_NUM_LABELS: usize = 8;

pub(crate) const MAX_JUMPS: u8 = 5;

pub(crate) const MAX_LABEL_SIZE: usize = 63;
pub(crate) const MAX_NAME_SIZE: usize = 255;

/// An error was encountered when trying to work with a domain name
#[derive(Error, Debug)]
pub enum NameError {
    /// Some label in the DNS packet it too long, overflowing the packet or not following the DNS specification.
    #[error(
        "Specified label length ({0}) is empty or is bigger than DNS specification (maximum {}).",
        MAX_LABEL_SIZE
    )]
    LabelLength(usize),
    /// Some label in one of the domain names is not valid because it contains characters that are not alphanumeric or `-`.
    #[error("The provided label is not a valid domain name label")]
    LabelContent,
    /// One of the labels in the packet has a length that is bigger than the DNS specification.
    #[error(
        "Name length ({0}) is too long, is bigger than DNS specification (maximum {}).",
        MAX_NAME_SIZE
    )]
    NameLength(usize),
}

/// A domain name represented as an inverted list of labels.
#[derive(Clone)]
pub struct Name<'a> {
    /// Domain name labels
    labels: Vec<&'a str>,
    /// Length of the domain name
    len: u8,
}

type IterHuman<'a> = Rev<IterHierarchy<'a>>;
type IterHierarchy<'a> = Copied<std::slice::Iter<'a, &'a str>>;

impl fmt::Display for Name<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for l in self.iter_human() {
            write!(f, "{}.", l)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for l in self.iter_human() {
            write!(f, "{}.", l)?;
        }
        Ok(())
    }
}

impl Default for Name<'_> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl From<Name<'_>> for Vec<u8> {
    #[inline]
    fn from(name: Name<'_>) -> Self {
        let mut out = Vec::with_capacity(name.len as _);
        name.serialize(&mut out);
        out
    }
}

impl<'a> TryFrom<&'a str> for Name<'a> {
    type Error = NameError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let mut name = Name::default();
        for label in value.rsplit('.') {
            name.push_label(label)?;
        }
        Ok(name)
    }
}

impl<'a> Name<'a> {
    /// Parse from the specified `buff`, starting at position `pos`.
    ///
    /// # Errors
    ///
    /// It will error if the buffer does not contain a valid domain name. If the domain name
    /// has been compressed the buffer should include all previous bytes from the DNS packet
    /// to be considered valid. Jump pointers should only point backwards inside the `buf`.
    #[inline]
    pub fn parse(buff: &'a [u8], pos: usize) -> Result<(Self, usize), ParseError> {
        let mut name = Name::new();
        let blen = buff.len();
        let (mut pos, mut size, mut jumps) = (pos, 0, 0);
        loop {
            if jumps > MAX_JUMPS {
                Err(ParseError::ExcesiveJumps(jumps))?;
            }
            match read_label_metadata(buff, pos)? {
                LabelMeta::Pointer(ptr) if ptr >= pos => Err(ParseError::InvalidJump)?,
                LabelMeta::Size(s) if s > MAX_LABEL_SIZE => Err(NameError::LabelLength(s))?,
                LabelMeta::Size(s) if blen <= pos + s => Err(NameError::LabelLength(s))?,
                LabelMeta::Size(s) if name.len as usize + s > MAX_NAME_SIZE => {
                    Err(NameError::NameLength(name.len as usize + s))?
                }
                LabelMeta::Size(s) if jumps == 0 => {
                    name.push_bytes(&buff[pos + 1..pos + s + 1])?;
                    pos += s + 1;
                    size += s + 1;
                }
                LabelMeta::Size(s) => {
                    name.push_bytes(&buff[pos + 1..pos + s + 1])?;
                    pos += s + 1;
                }
                LabelMeta::Pointer(ptr) if jumps == 0 => {
                    (pos, size, jumps) = (ptr, size + 2, jumps + 1);
                }
                LabelMeta::Pointer(ptr) => (pos, jumps) = (ptr, jumps + 1),
                LabelMeta::End if jumps == 0 => {
                    name.labels.reverse();
                    return Ok((name, size + 1));
                }
                LabelMeta::End => {
                    name.labels.reverse();
                    return Ok((name, size));
                }
            }
        }
    }

    /// Safely push a slice of bytes as as a subdomain label.
    fn push_bytes(&mut self, bytes: &'a [u8]) -> Result<(), NameError> {
        if valid_label(bytes) {
            // SAFETY: Because we have verified that the label is only ASCII alphanumeric + `-`
            // we now the label is valid UTF8.
            let label = unsafe { str::from_utf8_unchecked(bytes) };
            self.labels.push(label);
            // SAFETY: It wont overflow because valid labels have a length that fits in one byte.
            self.len += bytes.len() as u8 + 1;
            Ok(())
        } else {
            Err(NameError::LabelContent)
        }
    }

    /// Serialize the [Name] and append it tho the end of the provided `packet`
    #[inline]
    pub fn serialize(&self, packet: &mut Vec<u8>) {
        for label in self.iter_human() {
            packet.push(label.len() as _);
            packet.extend(label.as_bytes());
        }
        packet.push(0u8);
    }

    /// Create a new, empty, domain name.
    ///
    /// ```
    /// # use dominion_parser::body::name::Name;
    /// let name = Name::new();
    /// assert_eq!(name.to_string(), "".to_string())
    /// ```
    #[inline]
    pub fn new() -> Self {
        Name {
            labels: Vec::with_capacity(INIT_NUM_LABELS),
            len: 0,
        }
    }

    /// Obtain the top level domain (TLD) of the provided domain name.
    ///
    /// ```
    /// # use dominion_parser::body::name::Name;
    /// let mut name = Name::try_from("example.com").unwrap();
    /// assert_eq!(name.tld(), Some("com"))
    /// ```
    #[inline]
    pub fn tld(&self) -> Option<&str> {
        self.labels.first().copied()
    }

    /// Push a new label to the end of the domain name, as a subdomain of the current one.
    ///
    /// # Error
    ///
    /// Will error if the label is not a valid DNS label, or if the resulting Domain name is too big.
    ///
    /// ```
    /// # use dominion_parser::body::name::Name;
    /// let mut name = Name::new();
    /// name.push_label("com").unwrap();
    /// name.push_label("example").unwrap();
    /// assert_eq!(name.to_string(), "example.com.".to_string())
    /// ```
    #[inline]
    pub fn push_label(&mut self, label: &'a str) -> Result<(), NameError> {
        let len = label.len();
        if label.is_empty() || len > MAX_LABEL_SIZE {
            Err(NameError::LabelLength(len))
        } else if len + self.len as usize > MAX_NAME_SIZE {
            Err(NameError::NameLength(len + self.len as usize))
        } else if !valid_label(label.as_bytes()) {
            Err(NameError::LabelContent)
        } else {
            // SAFETY: It wont overflow because we have checked that the domain name length is not bigger than 255.
            self.len += len as u8;
            self.labels.push(label);
            Ok(())
        }
    }

    /// Get the number of labels in the domain name.
    ///
    /// ```
    /// # use dominion_parser::body::name::Name;
    /// let mut name = Name::try_from("example.com").unwrap();
    /// assert_eq!(2, name.label_count())
    /// ```
    #[inline]
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Check if `sub` is a subdomain of the current domain name.
    ///
    /// ```
    /// # use dominion_parser::body::name::Name;
    /// let mut name = Name::try_from("example.com").unwrap();
    /// let mut sub = Name::try_from("subdomain.example.com").unwrap();
    ///
    /// assert!(name.is_subdomain(&sub))
    /// ```
    #[inline]
    pub fn is_subdomain(&self, sub: &Name<'_>) -> bool {
        if self.labels.len() > sub.labels.len() {
            false
        } else {
            zip(self.iter_hierarchy(), sub.iter_hierarchy()).fold(true, |acc, (x, y)| acc && x == y)
        }
    }

    /// Return an iterator over the labels in human order.
    ///
    /// ```
    /// # use dominion_parser::body::name::Name;
    /// let mut name = Name::try_from("subdomain.example.com").unwrap();
    /// let mut human = name.iter_human();
    ///
    /// assert_eq!(human.next(), Some("subdomain"));
    /// assert_eq!(human.next(), Some("example"));
    /// assert_eq!(human.next(), Some("com"));
    /// ```
    #[inline]
    pub fn iter_human(&self) -> IterHuman<'_> {
        self.iter_hierarchy().rev()
    }

    /// Return an iterator over the labels in hierarchical order.
    ///
    /// ```
    /// # use dominion_parser::body::name::Name;
    /// let mut name = Name::try_from("subdomain.example.com").unwrap();
    /// let mut hierarchy = name.iter_hierarchy();
    ///
    /// assert_eq!(hierarchy.next(), Some("com"));
    /// assert_eq!(hierarchy.next(), Some("example"));
    /// assert_eq!(hierarchy.next(), Some("subdomain"));
    /// ```
    #[inline]
    pub fn iter_hierarchy(&self) -> IterHierarchy<'_> {
        self.labels.iter().copied()
    }
}

/// A label can only contain a `-` or alphanumeric characters, and must begin with a letter.
fn valid_label(label: &[u8]) -> bool {
    let mut bytes = label.iter();
    if let Some(b) = bytes.next() && b.is_ascii_alphabetic() {
        bytes.filter(|x| !matches!(x, b'-' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')).count() == 0
    } else {
        false
    }
}

enum LabelMeta {
    End,
    // Although it is really an u8 because it is used for indexing we give an usize
    Size(usize),
    // Although it is really an u16 because it is used for indexing we give an usize
    Pointer(usize),
}

#[inline]
fn read_label_metadata(buff: &[u8], pos: usize) -> Result<LabelMeta, ParseError> {
    let b = safe_u8_read(buff, pos)?;
    match b {
        0 => Ok(LabelMeta::End),
        1..=0b0011_1111 => Ok(LabelMeta::Size(b as _)),
        0b1100_0000..=0xFF => Ok(LabelMeta::Pointer(
            (safe_u16_read(buff, pos)? ^ 0b1100_0000_0000_0000) as _,
        )),
        _ => Err(ParseError::LabelPrefix(b))?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_labels() {
        let valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
        let invalid = "hello.world";
        assert!(valid_label(valid.as_bytes()));
        assert!(!valid_label(invalid.as_bytes()));
    }

    #[test]
    fn no_jumps() {
        let buff = [
            5, 104, 101, 108, 108, 111, // hello
            5, 119, 111, 114, 108, 100, // world
            3, 99, 111, 109, // com
            0, 1, 1, 1, // <end>
        ];
        let (name, n) = Name::parse(&buff[..], 0).unwrap();
        assert_eq!(n, 17);
        assert_eq!(name.to_string(), "hello.world.com.".to_string())
    }

    #[test]
    fn with_jumps() {
        let buff = [
            5, 119, 111, 114, 108, 100, // world
            3, 99, 111, 109, // com
            0, 1, 1, 1, // <end>
            5, 104, 101, 108, 108, 111, // hello
            192, 0, 1, 1, 1, 1, 1, 1, // <jump to 0>
        ];
        let (name, n) = Name::parse(&buff[..], 14).unwrap();
        assert_eq!(n, 8);
        assert_eq!(name.to_string(), "hello.world.com.".to_string())
    }

    #[test]
    fn name_parse_with_jumps() {
        let buff = [
            5, 119, 111, 114, 108, 100, // world
            3, 99, 111, 109, // com
            0, 1, 1, 1, // <end>
            5, 104, 101, 108, 108, 111, // hello
            192, 0, 1, 1, 1, 1, 1, 1, // <jump to 0>
        ];
        let (name, n) = Name::parse(&buff[..], 14).unwrap();
        assert_eq!(n, 8);
        assert_eq!(name.to_string(), "hello.world.com.".to_string())
    }

    #[test]
    fn serialize() {
        let buff = [
            5, 104, 101, 108, 108, 111, // hello
            5, 119, 111, 114, 108, 100, // world
            3, 99, 111, 109, // com
            0, 1, 1, 1, // <end>
        ];
        let (name, _) = Name::parse(&buff[..], 0).unwrap();
        assert_eq!(name.to_string(), "hello.world.com.".to_string());
        let out: Vec<u8> = name.into();
        assert_eq!(&buff[..17], &out[..17])
    }

    #[test]
    fn get_tld() {
        let mut name = Name::new();
        name.push_label("com").unwrap();
        name.push_label("world").unwrap();
        name.push_label("hello").unwrap();

        let tld = name.tld();
        assert_eq!(tld, Some("com"));
    }

    #[test]
    fn add_str_subdomain() {
        let buff = [5, 119, 111, 114, 108, 100, 3, 99, 111, 109, 0, 1, 1, 1]; // world.com
        let (mut name, _) = Name::parse(&buff[..], 0).unwrap();
        name.push_label("hello").unwrap();
        assert_eq!(name.to_string(), "hello.world.com.".to_string())
    }

    #[test]
    fn add_string_subdomain() {
        let sub = String::from("hello");
        let buff = [5, 119, 111, 114, 108, 100, 3, 99, 111, 109, 0, 1, 1, 1]; // world.com
        let (mut name, _) = Name::parse(&buff[..], 0).unwrap();
        name.push_label(&sub[..]).unwrap();
        assert_eq!(name.to_string(), "hello.world.com.".to_string())
    }

    #[test]
    fn iterate_human() {
        let mut name = Name::new();
        name.push_label("com").unwrap();
        name.push_label("world").unwrap();
        name.push_label("hello").unwrap();

        let mut human = name.iter_human();
        assert_eq!(human.next(), Some("hello"));
        assert_eq!(human.next(), Some("world"));
        assert_eq!(human.next(), Some("com"));
    }

    #[test]
    fn iterate_hierarchy() {
        let mut name = Name::new();
        name.push_label("com").unwrap();
        name.push_label("world").unwrap();
        name.push_label("hello").unwrap();

        let mut human = name.iter_hierarchy();
        assert_eq!(human.next(), Some("com"));
        assert_eq!(human.next(), Some("world"));
        assert_eq!(human.next(), Some("hello"));
    }

    #[test]
    fn check_subdomain() {
        let mut parent = Name::new();
        parent.push_label("com").unwrap();
        parent.push_label("world").unwrap();

        let mut sub = Name::new();
        sub.push_label("com").unwrap();
        sub.push_label("world").unwrap();
        sub.push_label("hello").unwrap();

        assert!(parent.is_subdomain(&sub));
        assert!(!sub.is_subdomain(&parent));
    }

    #[test]
    fn root_subdomain() {
        let root = Name::default();
        let subd = Name::try_from("example.com").unwrap();

        assert!(root.is_subdomain(&subd));
        assert!(!subd.is_subdomain(&root));
    }
}
