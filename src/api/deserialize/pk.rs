use crate::api::types::{PKRequest, PK};

impl PKRequest {
    pub fn deserialize(proto: PKRequest) -> Option<PK> {
        return Option::from(
            PK {
                id: proto.id as usize,
                n: proto.n as usize
            }
        )
    }
}