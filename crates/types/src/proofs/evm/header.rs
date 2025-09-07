use alloy::primitives::Bytes;
use serde::{Deserialize, Serialize};

use crate::proofs::header::{HeaderProof, HeaderProofKeccak};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, Default)]
pub struct Header {
    pub rlp: Bytes,
    pub proof: HeaderProof,
}

// New Header struct for Keccak that preserves full 256-bit precision
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, Default)]
pub struct HeaderKeccak {
    pub rlp: Bytes,
    pub proof: HeaderProofKeccak,
}
