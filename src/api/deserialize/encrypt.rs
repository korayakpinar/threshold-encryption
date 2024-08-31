#![allow(unused_imports)]
use std::io::Cursor;

use ark_serialize::CanonicalDeserialize;

use crate::{api::types::{Encrypt, EncryptRequest, E}, setup::PublicKey};

impl EncryptRequest {
    pub fn deserialize(self) -> Option<Encrypt> {  
        Option::from(
            Encrypt {
                msg: self.msg,
                t: self.t as usize,
                n: self.n as usize
            }
        )
    }
}