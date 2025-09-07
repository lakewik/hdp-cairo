use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::mmr::MmrMeta;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default, Hash)]
pub struct HeaderMmrMeta<T> {
    pub headers: Vec<T>,
    pub mmr_meta: MmrMeta,
}

// New struct for Keccak that preserves full 256-bit precision
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default, Hash)]
pub struct HeaderMmrMetaKeccak<T> {
    pub headers: Vec<T>,
    pub mmr_meta: MmrMeta,
}

// Enum to handle different hash types without truncation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MmrPathElement {
    Felt252(Felt252),
    HexString(String),
}

// Custom serialization to maintain the original JSON format
impl Serialize for MmrPathElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            MmrPathElement::Felt252(felt) => serializer.serialize_str(&format!("0x{:x}", felt)),
            MmrPathElement::HexString(hex) => serializer.serialize_str(hex),
        }
    }
}

// Custom deserialization to handle both formats
impl<'de> Deserialize<'de> for MmrPathElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Try to parse as Felt252 first, if it fails, store as hex string
        if let Ok(felt) = Felt252::from_hex(&s) {
            Ok(MmrPathElement::Felt252(felt))
        } else {
            Ok(MmrPathElement::HexString(s))
        }
    }
}

impl Default for MmrPathElement {
    fn default() -> Self {
        MmrPathElement::Felt252(Felt252::ZERO)
    }
}

// Implement From<MmrPathElement> for MaybeRelocatable to work with Cairo
impl From<MmrPathElement> for cairo_vm::types::relocatable::MaybeRelocatable {
    fn from(element: MmrPathElement) -> Self {
        match element {
            MmrPathElement::Felt252(felt) => cairo_vm::types::relocatable::MaybeRelocatable::from(felt),
            MmrPathElement::HexString(hex) => {
                // For hex strings, we need to convert to Felt252 first
                // This will truncate for Keccak, but it's needed for Cairo compatibility
                let felt = Felt252::from_hex(&hex).unwrap_or(Felt252::ZERO);
                cairo_vm::types::relocatable::MaybeRelocatable::from(felt)
            }
        }
    }
}

// Implement to_bytes_be for compatibility
impl MmrPathElement {
    pub fn to_bytes_be(&self) -> Vec<u8> {
        match self {
            MmrPathElement::Felt252(felt) => felt.to_bytes_be().to_vec(),
            MmrPathElement::HexString(hex) => {
                // For hex strings, convert to bytes
                let hex_clean = hex.trim_start_matches("0x");
                // Simple hex decoding without external crate
                let mut bytes = Vec::new();
                for i in (0..hex_clean.len()).step_by(2) {
                    if i + 1 < hex_clean.len() {
                        let byte_str = &hex_clean[i..i+2];
                        if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
                            bytes.push(byte);
                        }
                    }
                }
                bytes
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, Default)]
#[serde_as]
pub struct HeaderProof {
    pub leaf_idx: u64,
    pub mmr_path: Vec<MmrPathElement>,
    pub element_hash: Option<String>,
}

// Custom serialization wrapper that outputs the correct format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct HeaderProofSerialized {
    pub leaf_idx: u64,
    pub mmr_path: Vec<String>,
    pub element_hash: Option<String>,
}

impl From<&HeaderProof> for HeaderProofSerialized {
    fn from(proof: &HeaderProof) -> Self {
        let mmr_path: Vec<String> = proof.mmr_path.iter().map(|element| match element {
            MmrPathElement::Felt252(felt) => format!("0x{:x}", felt),
            MmrPathElement::HexString(hex) => hex.clone(),
        }).collect();
        
        HeaderProofSerialized {
            leaf_idx: proof.leaf_idx,
            mmr_path,
            element_hash: proof.element_hash.clone(),
        }
    }
}


// New struct for Keccak proofs that preserves full 256-bit precision
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, Default)]
pub struct HeaderProofKeccak {
    pub leaf_idx: u64,
    pub mmr_path: Vec<String>, // Store as hex strings to preserve full 256-bit precision
    pub element_hash: Option<String>,
}
