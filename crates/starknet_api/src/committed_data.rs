//! Admission policy for appchain committed-data adapters.

use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use crate::StarknetApiError;
use crate::core::ContractAddress;

/// Bounds the Cairo policy scan and configuration input size.
pub const MAX_COMMITTED_DATA_READERS: usize = 64;

/// Approved adapter storage addresses, in canonical ascending order.
/// Adapters must enforce authorized roots and valid indices; arbitrary root selection can
/// deliberately trigger an unprovable availability failure after expensive execution without paying
/// a transaction fee. An empty list denies every caller, including when the extension is activated.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CommittedDataReaders(Vec<ContractAddress>);

impl CommittedDataReaders {
    /// Validates the size and addresses, rejects duplicates and canonicalizes ordering.
    pub fn new(mut readers: Vec<ContractAddress>) -> Result<Self, StarknetApiError> {
        if readers.len() > MAX_COMMITTED_DATA_READERS {
            return Err(invalid_policy("too many committed-data adapters"));
        }
        for reader in &readers {
            ContractAddress::try_from(*reader.0.key())?;
            if *reader.0.key() == Felt::ZERO {
                return Err(invalid_policy("committed-data adapter cannot be zero"));
            }
        }
        readers.sort_unstable();
        if readers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid_policy("duplicate committed-data adapter"));
        }
        Ok(Self(readers))
    }

    /// Returns the canonical addresses committed into the OS configuration.
    pub fn as_slice(&self) -> &[ContractAddress] {
        &self.0
    }

    pub fn contains(&self, address: Felt) -> bool {
        ContractAddress::try_from(address)
            .is_ok_and(|address| self.0.binary_search(&address).is_ok())
    }
}

/// Comma-separated adapter addresses for CLI/environment configuration.
impl std::str::FromStr for CommittedDataReaders {
    type Err = StarknetApiError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Ok(Self::default());
        }
        let mut readers = Vec::new();
        for item in value.split(',') {
            if readers.len() == MAX_COMMITTED_DATA_READERS {
                return Err(invalid_policy("too many committed-data adapters"));
            }
            let felt = Felt::from_hex(item.trim())
                .map_err(|_| invalid_policy("invalid committed-data adapter address"))?;
            readers.push(ContractAddress::try_from(felt)?);
        }
        Self::new(readers)
    }
}

impl<'de> Deserialize<'de> for CommittedDataReaders {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReadersVisitor;
        impl<'de> serde::de::Visitor<'de> for ReadersVisitor {
            type Value = CommittedDataReaders;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("at most 64 unique committed-data adapter addresses")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut readers = Vec::new();
                while let Some(reader) = sequence.next_element()? {
                    if readers.len() == MAX_COMMITTED_DATA_READERS {
                        return Err(serde::de::Error::custom("too many committed-data adapters"));
                    }
                    readers.push(reader);
                }
                CommittedDataReaders::new(readers).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_seq(ReadersVisitor)
    }
}

fn invalid_policy(message: &str) -> StarknetApiError {
    StarknetApiError::OutOfRange { string: message.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_data_adapters_are_bounded_canonical_and_explicit() {
        let readers: CommittedDataReaders = serde_json::from_str(r#"["0x2","0x1"]"#).unwrap();
        assert_eq!(serde_json::to_string(&readers).unwrap(), r#"["0x1","0x2"]"#);
        assert_eq!(readers, "0x2,0x1".parse().unwrap());
        assert!("0x1,0x1".parse::<CommittedDataReaders>().is_err());
        assert!("0x0".parse::<CommittedDataReaders>().is_err());
        assert!(readers.contains(Felt::ONE));
        assert!(!readers.contains(Felt::from(3_u32)));
        assert!(!CommittedDataReaders::default().contains(Felt::ONE));
        assert!(serde_json::from_str::<CommittedDataReaders>(r#"["0x1","0x1"]"#).is_err());
        assert!(serde_json::from_str::<CommittedDataReaders>(r#"["0x0"]"#).is_err());
        let too_many: Vec<_> = (1..=MAX_COMMITTED_DATA_READERS + 1).map(Felt::from).collect();
        assert!(
            serde_json::from_value::<CommittedDataReaders>(serde_json::to_value(too_many).unwrap())
                .is_err()
        );
    }
}
