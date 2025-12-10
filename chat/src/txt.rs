// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::BTreeMap, path::Path, str};

use dominion::{DnsHeader, DnsPacket, Flags, Name, ResourceRecord};

use memmap2::Mmap;

const MAX_TXT_SIZE: usize = 255;

#[derive(Debug)]
pub(crate) struct TxtHandler {
    files: BTreeMap<String, Mmap>,
}

impl TxtHandler {
    pub fn new<I, P>(mapping: I) -> Result<Self, &'static str>
    where
        I: Iterator<Item = (String, P)>,
        P: AsRef<Path>,
    {
        use std::fs::File;
        let mut files = BTreeMap::new();
        for (k, p) in mapping {
            let fd = File::open(p).map_err(|_| "could not open a file")?;
            // SAFETY: Because we copy the bytes from the appropiate part of the file
            // before we use them, a change in the underlying file will not produce UB
            let v = unsafe { Mmap::map(&fd).map_err(|_| "could not read the file")? };
            files.insert(k, v);
        }
        Ok(Self { files })
    }

    pub fn response<'a>(
        &self,
        question: &'a DnsPacket<'a>,
        filter: &Name<'_>,
        xor: &Option<crate::Xor>,
    ) -> DnsPacket<'a> {
        let id = question.header.id;
        let name = &question.questions[0].name;

        // Si no es un subdominio no es una petición nuestra
        if !filter.is_subdomain(name) {
            return super::refused(id);
        }

        // Obtenemos la clave del subdominio
        let mut labels = name.iter_hierarchy();
        let label = labels
            .nth(filter.label_count())
            .expect("Because it is a subdomain it should have at least one more label");

        // Si no podemos leer el cacho es que algo ha ido mal y rechazamos
        // la solicitud.
        let Some(chunk) = self.read_chunk(label) else {
            return super::refused(id);
        };
        let chunk = match xor {
            Some(xor) => encrypt(chunk, xor.key),
            None => str::from_utf8(chunk)
                .expect("clear text files can only be text")
                .to_string(),
        };

        let header = DnsHeader {
            id,
            flags: flags(),
            questions: 1,
            answers: 1,
            authority: 0,
            additional: 0,
        };
        DnsPacket {
            header,
            questions: question.questions.clone(),
            answers: vec![answer(name, chunk)],
            authority: vec![],
            additional: vec![],
        }
    }

    fn read_chunk<'a>(&'a self, key: &str) -> Option<&'a [u8]> {
        use std::cmp::min;
        // Key format <fileid>-<position> for example:
        //     file1-3
        fn parse_key(key: &str) -> Option<(&str, usize)> {
            let key_i = key.rsplit_once('-')?;
            let i = key_i.1.parse().ok()?;
            Some((key_i.0, i))
        }

        let (file, i) = parse_key(key)?;
        let map = self.files.get(&file.to_ascii_lowercase())?;
        let i = i * MAX_TXT_SIZE / 2;
        let j = min(map.len(), i + MAX_TXT_SIZE / 2);
        map.get(i..j)
    }
}

fn encrypt(label: &[u8], key: u8) -> String {
    let out: Vec<u8> = label.iter().map(|b| b ^ key).collect();
    hex::encode(out)
}

fn flags() -> Flags {
    use dominion::*;

    Flags {
        qr: QueryResponse::Response,
        opcode: OpCode::Query,
        aa: AuthoritativeAnswer::Authoritative,
        tc: TrunCation::NotTruncated,
        rd: RecursionDesired::NotDesired,
        ra: RecursionAvailable::NotAvailable,
        z: Zero::Zero,
        ad: AuthenticData::NotAuthentic,
        cd: CheckingDisabled::Disabled,
        rcode: ResponseCode::NoError,
    }
}

fn answer<'a>(name: &Name<'a>, txt: String) -> ResourceRecord<'a> {
    use dominion::RecordPreamble;
    let txt_len: u16 = txt
        .len()
        .try_into()
        .expect("TXT message max length is 255 bytes");
    let preamble = RecordPreamble {
        name: name.clone(),
        rrtype: dominion::Type::Txt,
        class: dominion::Class::IN,
        ttl: 0,
        rdlen: 1u16 + txt_len,
    };
    ResourceRecord {
        preamble,
        data: dominion::RecordData::Txt(txt.into()),
    }
}
