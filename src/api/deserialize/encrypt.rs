use std::io::Cursor;

use ark_serialize::CanonicalDeserialize;

use crate::{api::types::{Encrypt, EncryptRequest, E}, setup::PublicKey};

impl EncryptRequest {
    pub fn deserialize(self) -> Option<Encrypt> {
        let mut pks = Vec::new();
        // println!("len: {}", proto.pks.len());
        for (idx, pk) in self.pks.iter().enumerate() {
            if pk.is_empty() {
                log::error!("pk is empty /encrypt {}", idx);
                continue;
            }
            let cur = Cursor::new(pk);
            let tmp_pk = PublicKey::<E>::deserialize_uncompressed_unchecked(cur);
            if tmp_pk.is_err() {
                log::error!("{:#?}", pk);
                log::error!("can't deserialize pk {}", idx);
                return None;
            }
            pks.push(tmp_pk.unwrap());
        }
        
        Option::from(
            Encrypt {
                msg: self.msg,
                pks,
                t: self.t as usize,
                n: self.n as usize
            }
        )
    }
}