// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::BTreeMap, path::Path, str, sync::Arc};

use dominion::{DnsHeader, DnsPacket, Flags, Name, ResourceRecord};

use memmap2::Mmap;

const MAX_TXT_SIZE: usize = 255;

#[derive(Debug)]
pub(crate) struct TxtHandler<'a> {
    files: BTreeMap<String, Mmap>,
    filter: Arc<Name<'a>>,
}

impl<'me> TxtHandler<'me> {
    pub fn new<I, P>(mapping: I, filter: Arc<Name<'me>>) -> Result<Self, &'static str>
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
        Ok(Self { files, filter })
    }

    pub fn response<'a>(&self, question: &'a DnsPacket<'a>) -> DnsPacket<'a> {
        let id = question.header.id;
        let name = &question.questions[0].name;

        // Si no es un subdominio no es una petición nuestra
        if !self.filter.is_subdomain(name) {
            return super::refused(id);
        }

        // Obtenemos la clave del subdominio
        let mut labels = name.iter_hierarchy();
        let label = labels
            .nth(self.filter.label_count())
            .expect("Because it is a subdomain it should have at least one more label");
        log(label);

        // Si no podemos leer el cacho es que algo ha ido mal y rechazamos
        // la solicitud.
        let Some(chunk) = self.read_chunk(label) else {
            return super::refused(id);
        };
        let chunk = str::from_utf8(chunk)
            .expect("files can only be text")
            .to_string();

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
        // If there is no position we asume initial position
        let (file, i) = match key.rsplit_once('-') {
            None => (key, 0),
            Some(key_i) => (key_i.0, key_i.1.parse().ok()?),
        };

        // Si lo mandamos cifrado y codificado el tamaño será más
        // grande por lo que este código debería cambiar. Se limita
        // a mandar respuestas en claro o cifradas de forma externa.
        let map = self.files.get(&file.to_ascii_lowercase())?;
        let i = i * MAX_TXT_SIZE;
        let j = min(map.len(), i + MAX_TXT_SIZE);
        map.get(i..j)
    }
}

fn log(label: &'_ str) {
    println!("🗒️ Asked for {label}\n\n");
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
