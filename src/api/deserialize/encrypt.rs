use std::io::Cursor;

use ark_serialize::CanonicalDeserialize;

use crate::api::types::{Encrypt, EncryptRequest};

impl EncryptRequest {
    pub fn deserialize(proto: EncryptRequest) -> Option<Encrypt> {
        let mut pks = Vec::new();
        // println!("len: {}", proto.pks.len());
        for (idx, pk) in proto.pks.iter().enumerate() {
            if pk.is_empty() {
                continue;
            }
            let cur = Cursor::new(pk);
            let tmp_pk = CanonicalDeserialize::deserialize_compressed(cur);
            if tmp_pk.is_err() {
                log::error!("can't deserialize pk {}", idx);
                return None;
            }
            pks.push(tmp_pk.unwrap());
        }
        
        Option::from(
            Encrypt {
                msg: proto.msg,
                pks,
                t: proto.t as usize,
                n: proto.n as usize
            }
        )
    }
}