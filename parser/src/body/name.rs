// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::binutils::*;
use crate::ParseError;
use std::fmt;
use std::iter::zip;
use std::iter::Copied;
use std::iter::Rev;
use std::str;

const INIT_NUM_LABELS: usize = 4;

pub(crate) const MAX_JUMPS: u8 = 5;

pub(crate) const MAX_LABEL_SIZE: usize = 63;
pub(crate) const MAX_NAME_SIZE: usize = 255;

/// A domain name represented as an inverted list of labels.
#[derive(Clone)]
pub struct Name<'a>(Vec<&'a str>);

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
        let mut out = Vec::with_capacity(name.0.len() * 8);
        name.serialize(&mut out);
        out
    }
}

impl<'a> TryFrom<&'a str> for Name<'a> {
    type Error = ParseError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let mut name = Name::default();
        for label in value.rsplit('.') {
            if label.len() < MAX_LABEL_SIZE {
                name.push_label(label);
            } else {
                Err(ParseError::LabelLength(label.len()))?
            }
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
        let (positions, n) = find_labels(buff, pos)?;
        let name = parse_labels(buff, positions)?;
        // TODO: Max name size
        Ok((name, n))
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
        Name(Vec::with_capacity(INIT_NUM_LABELS))
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
        self.0.first().copied()
    }

    /// Push a new label to the end of the domain name, as a subdomain of the current one. Empty
    /// labels will be ignored.
    ///
    /// ```
    /// # use dominion_parser::body::name::Name;
    /// let mut name = Name::new();
    /// name.push_label("com");
    /// name.push_label("example");
    /// assert_eq!(name.to_string(), "example.com.".to_string())
    /// ```
    #[inline]
    pub fn push_label(&mut self, label: &'a str) {
        if !label.is_empty() {
            self.0.push(label);
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
        self.0.len()
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
        if self.0.len() > sub.0.len() {
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
        self.0.iter().copied()
    }
}

type LabelsPositions = Vec<(usize, usize)>;

#[inline]
fn parse_labels(buff: &[u8], positions: LabelsPositions) -> Result<Name<'_>, ParseError> {
    let mut name = Name::new();
    for (pos, size) in positions.into_iter().rev() {
        let label = str::from_utf8(&buff[pos..pos + size]).map_err(ParseError::from)?;
        name.push_label(label);
    }
    Ok(name)
}

fn find_labels(buff: &[u8], pos: usize) -> Result<(LabelsPositions, usize), ParseError> {
    let blen = buff.len();
    let mut positions = LabelsPositions::new();
    let (mut pos, mut size, mut jumps) = (pos, 0, 0);
    loop {
        if jumps > MAX_JUMPS {
            Err(ParseError::ExcesiveJumps(jumps))?;
        }
        match read_label_metadata(buff, pos)? {
            LabelMeta::Size(s) if s > MAX_LABEL_SIZE => Err(ParseError::LabelLength(s))?,
            LabelMeta::Size(s) if blen <= pos + s => Err(ParseError::LabelLength(s))?,
            LabelMeta::Pointer(ptr) if ptr >= pos => Err(ParseError::InvalidJump)?,
            LabelMeta::Size(s) if jumps == 0 => {
                positions.push((pos + 1, s));
                pos += s + 1;
                size += s + 1;
            }
            LabelMeta::Size(s) => {
                positions.push((pos + 1, s));
                pos += s + 1;
            }
            LabelMeta::Pointer(ptr) if jumps == 0 => {
                (pos, size, jumps) = (ptr, size + 2, jumps + 1);
            }
            LabelMeta::Pointer(ptr) => (pos, jumps) = (ptr, jumps + 1),
            LabelMeta::End if jumps == 0 => return Ok((positions, size + 1)),
            LabelMeta::End => return Ok((positions, size)),
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
    fn find_position_no_jumps() {
        let buff = [
            5, 104, 101, 108, 108, 111, // hello
            5, 119, 111, 114, 108, 100, // world
            3, 99, 111, 109, // com
            0, 1, 1, 1, // <end>
        ];
        let (positions, n) = find_labels(&buff[..], 0).unwrap();
        assert_eq!(n, 17);
        assert_eq!(positions, vec![(1, 5), (7, 5), (13, 3)])
    }

    #[test]
    fn find_position_with_jumps() {
        let buff = [
            5, 119, 111, 114, 108, 100, // world
            3, 99, 111, 109, // com
            0, 1, 1, 1, // <end>
            5, 104, 101, 108, 108, 111, // hello
            192, 0, 1, 1, 1, 1, 1, 1, // <jump to 0>
        ];
        let (positions, n) = find_labels(&buff[..], 14).unwrap();
        assert_eq!(n, 8);
        assert_eq!(positions, vec![(15, 5), (1, 5), (7, 3)])
    }

    #[test]
    fn no_jumps() {
        let buff = [
            5, 104, 101, 108, 108, 111, // hello
            5, 119, 111, 114, 108, 100, // world
            3, 99, 111, 109, // com
            0, 1, 1, 1, // <end>
        ];
        let (positions, n) = find_labels(&buff[..], 0).unwrap();
        let name = parse_labels(&buff[..], positions).unwrap();
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
        let (positions, n) = find_labels(&buff[..], 14).unwrap();
        let name = parse_labels(&buff[..], positions).unwrap();
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
        name.push_label("com");
        name.push_label("world");
        name.push_label("hello");

        let tld = name.tld();
        assert_eq!(tld, Some("com"));
    }

    #[test]
    fn add_str_subdomain() {
        let buff = [5, 119, 111, 114, 108, 100, 3, 99, 111, 109, 0, 1, 1, 1]; // world.com
        let (mut name, _) = Name::parse(&buff[..], 0).unwrap();
        name.push_label("hello");
        assert_eq!(name.to_string(), "hello.world.com.".to_string())
    }

    #[test]
    fn add_string_subdomain() {
        let sub = String::from("hello");
        let buff = [5, 119, 111, 114, 108, 100, 3, 99, 111, 109, 0, 1, 1, 1]; // world.com
        let (mut name, _) = Name::parse(&buff[..], 0).unwrap();
        name.push_label(&sub[..]);
        assert_eq!(name.to_string(), "hello.world.com.".to_string())
    }

    #[test]
    fn iterate_human() {
        let mut name = Name::new();
        name.push_label("com");
        name.push_label("world");
        name.push_label("hello");

        let mut human = name.iter_human();
        assert_eq!(human.next(), Some("hello"));
        assert_eq!(human.next(), Some("world"));
        assert_eq!(human.next(), Some("com"));
    }

    #[test]
    fn iterate_hierarchy() {
        let mut name = Name::new();
        name.push_label("com");
        name.push_label("world");
        name.push_label("hello");

        let mut human = name.iter_hierarchy();
        assert_eq!(human.next(), Some("com"));
        assert_eq!(human.next(), Some("world"));
        assert_eq!(human.next(), Some("hello"));
    }

    #[test]
    fn check_subdomain() {
        let mut parent = Name::new();
        parent.push_label("com");
        parent.push_label("world");

        let mut sub = Name::new();
        sub.push_label("com");
        sub.push_label("world");
        sub.push_label("hello");

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
