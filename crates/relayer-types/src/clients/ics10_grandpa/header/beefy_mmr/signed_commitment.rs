use crate::clients::ics10_grandpa::error::Error;
use crate::prelude::*;
use ibc_proto::ibc::lightclients::grandpa::v1::{
    Commitment as RawCommitment, PayloadItem as RawPayloadItem, Signature as RawSignature,
    SignedCommitment as RawSignedCommitment,
};
use ibc_proto::protobuf::Protobuf;

use serde::{Deserialize, Serialize};
/// signed commitment data
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommitment {
    /// commitment data being signed
    pub commitment: Option<Commitment>,
    /// all the signatures
    pub signatures: Vec<Signature>,
}

impl Protobuf<RawSignedCommitment> for SignedCommitment {}

impl TryFrom<RawSignedCommitment> for SignedCommitment {
    type Error = Error;

    fn try_from(raw: RawSignedCommitment) -> Result<Self, Self::Error> {
        Ok(Self {
            commitment: raw
                .commitment
                .map(TryInto::try_into)
                .map_or(Ok(None), |r| r.map(Some))?,
            signatures: raw
                .signatures
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, Self::Error>>()?,
        })
    }
}

impl From<SignedCommitment> for RawSignedCommitment {
    fn from(value: SignedCommitment) -> Self {
        Self {
            commitment: value.commitment.map(Into::into),
            signatures: value.signatures.into_iter().map(Into::into).collect(),
        }
    }
}

/// Signature with it`s index in merkle tree
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// signature leaf index in the merkle tree.
    pub index: u32,
    /// signature bytes
    pub signature: Vec<u8>,
}

impl Protobuf<RawSignature> for Signature {}

impl TryFrom<RawSignature> for Signature {
    type Error = Error;

    fn try_from(raw: RawSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            index: raw.index,
            signature: raw.signature,
        })
    }
}

impl From<Signature> for RawSignature {
    fn from(value: Signature) -> Self {
        Self {
            index: value.index,
            signature: value.signature,
        }
    }
}

/// Commitment message signed by beefy validators
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// array of payload items signed by Beefy validators
    pub payloads: Vec<PayloadItem>,
    /// block number for this commitment
    pub block_number: u32,
    /// validator set that signed this commitment
    pub validator_set_id: u64,
}

impl Protobuf<RawCommitment> for Commitment {}

impl TryFrom<RawCommitment> for Commitment {
    type Error = Error;

    fn try_from(raw: RawCommitment) -> Result<Self, Self::Error> {
        Ok(Self {
            payloads: raw
                .payloads
                .into_iter()
                .map(|payload_item| payload_item.try_into())
                .collect::<Result<Vec<_>, Self::Error>>()?,
            block_number: raw.block_number,
            validator_set_id: raw.validator_set_id,
        })
    }
}

impl From<Commitment> for RawCommitment {
    fn from(value: Commitment) -> Self {
        Self {
            payloads: value.payloads.into_iter().map(Into::into).collect(),
            block_number: value.block_number,
            validator_set_id: value.validator_set_id,
        }
    }
}

/// Actual payload items
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadItem {
    /// 2-byte payload id
    pub id: Vec<u8>,
    /// arbitrary length payload data., eg mmr_root_hash
    pub data: Vec<u8>,
}

impl Protobuf<RawPayloadItem> for PayloadItem {}

impl TryFrom<RawPayloadItem> for PayloadItem {
    type Error = Error;

    fn try_from(raw: RawPayloadItem) -> Result<Self, Self::Error> {
        Ok(Self {
            id: raw.id,
            data: raw.data,
        })
    }
}

impl From<PayloadItem> for RawPayloadItem {
    fn from(value: PayloadItem) -> Self {
        Self {
            id: value.id,
            data: value.data,
        }
    }
}
