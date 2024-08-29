use ark_serialize::CanonicalDeserialize;
use std::io::Cursor;

use crate::api::types::{PKRequest, PK};

impl PKRequest {
    pub fn deserialize(self) -> Option<PK> {
        let cur = Cursor::new(self.sk);
        let tmp = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp.is_err() {
            log::error!("can't read sk");
            return None;
        }
        let sk = tmp.unwrap();

        return Option::from(
            PK {
                sk,
                id: self.id as usize,
                n: self.n as usize
            }
        )
    }
}