// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Message, MessageHash, VerifyStatus};
use crate::{
    consensus::{DkgFailureProof, DkgFailureProofSet, DkgKey, ProofShare, Proven, Vote},
    crypto::Signature,
    error::{Error, Result},
    network::Network,
    relocation::{RelocateDetails, RelocatePayload, RelocatePromise},
    section::{EldersInfo, MemberInfo, Section, SectionChain},
};
use bls_dkg::key_gen::message::Message as DkgMessage;
use bytes::Bytes;
use hex_fmt::HexFmt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fmt::{self, Debug, Formatter},
};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
/// Message variant
pub(crate) enum Variant {
    /// Inform neighbours about our new section.
    NeighbourInfo {
        /// `EldersInfo` of the sender's section, with the proof chain.
        elders_info: Proven<EldersInfo>,
        /// Nonce that is derived from the incoming message that triggered sending this
        /// `NeighbourInfo`. It's purpose is to make sure that `NeighbourInfo`s that are identical
        /// but triggered by different messages are not filtered out.
        nonce: MessageHash,
    },
    /// User-facing message
    UserMessage(Bytes),
    /// Message sent to newly joined node containing the necessary info to become a member of our
    /// section.
    NodeApproval {
        elders_info: Proven<EldersInfo>,
        member_info: Proven<MemberInfo>,
    },
    /// Message sent to all members to update them about the state of our section.
    Sync {
        // Information about our section.
        section: Section,
        // Information about the rest of the network that we know of.
        network: Network,
    },
    /// Send from a section to the node to be immediately relocated.
    Relocate(RelocateDetails),
    /// Send:
    /// - from a section to a current elder to be relocated after they are demoted.
    /// - from the node to be relocated back to its section after it was demoted.
    RelocatePromise(RelocatePromise),
    /// Sent from a bootstrapping peer to the section that responded with a
    /// `GetSectionResponse::Succcess` to its `GetSectionQuery`.
    JoinRequest(Box<JoinRequest>),
    /// Response to outdated JoinRequest
    JoinRetry {
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
    },
    /// Sent from a node that can't establish the trust of the contained message to its original
    /// source in order for them to provide new proof that the node would trust.
    BouncedUntrustedMessage(Box<Message>),
    /// Sent from a node that doesn't know how to handle `message` to its elders in order for them
    /// to decide what to do with it (resend with more info or discard).
    BouncedUnknownMessage {
        /// The last section key of the sender.
        src_key: bls::PublicKey,
        /// The serialized original message.
        message: Bytes,
    },
    /// Sent to the new elder candidates to start the DKG process.
    DkgStart {
        /// The identifier of the DKG session to start.
        dkg_key: DkgKey,
        /// The DKG particpants.
        elders_info: EldersInfo,
    },
    /// Message exchanged for DKG process.
    DkgMessage {
        /// The identifier of the DKG session this message is for.
        dkg_key: DkgKey,
        /// The DKG message.
        message: DkgMessage,
    },
    /// Broadcasted to the other DKG participants when a DKG failure is observed.
    DkgFailureObservation {
        dkg_key: DkgKey,
        proof: DkgFailureProof,
    },
    /// Sent to the current elders by the DKG participants when at least majority of them observe
    /// a DKG failure.
    DkgFailureAgreement(DkgFailureProofSet),
    /// Message containing a single `Vote` to be accumulated in the vote accumulator.
    Vote {
        content: Vote,
        proof_share: ProofShare,
    },
    /// Challenge sent from existing elder nodes to the joining peer for resource proofing.
    ResourceChallenge {
        data_size: usize,
        difficulty: u8,
        nonce: [u8; 32],
        nonce_signature: Signature,
    },
}

impl Variant {
    pub(crate) fn verify<'a, I>(
        &self,
        proof_chain: Option<&SectionChain>,
        trusted_keys: I,
    ) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        let proof_chain = match self {
            Self::NodeApproval {
                elders_info,
                member_info,
            } => {
                let proof_chain = proof_chain.ok_or(Error::InvalidMessage)?;

                if !elders_info.verify(proof_chain) {
                    return Err(Error::InvalidMessage);
                }

                if !member_info.verify(proof_chain) {
                    return Err(Error::InvalidMessage);
                }

                proof_chain
            }
            Self::Sync { section, .. } => section.chain(),
            Self::NeighbourInfo { elders_info, .. } => {
                let proof_chain = proof_chain.ok_or(Error::InvalidMessage)?;

                if !elders_info.verify(proof_chain) {
                    return Err(Error::InvalidMessage);
                }

                proof_chain
            }
            _ => return Ok(VerifyStatus::Full),
        };

        if proof_chain.check_trust(trusted_keys) {
            Ok(VerifyStatus::Full)
        } else {
            Ok(VerifyStatus::Unknown)
        }
    }
}

impl Debug for Variant {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::NeighbourInfo { elders_info, nonce } => f
                .debug_struct("NeighbourInfo")
                .field("elders_info", elders_info)
                .field("nonce", nonce)
                .finish(),
            Self::UserMessage(payload) => write!(f, "UserMessage({:10})", HexFmt(payload)),
            Self::NodeApproval {
                elders_info,
                member_info,
            } => f
                .debug_struct("NodeApproval")
                .field("elders_info", elders_info)
                .field("member_info", member_info)
                .finish(),
            Self::Sync { section, network } => f
                .debug_struct("Sync")
                .field("elders_info", section.elders_info())
                .field("section_key", section.chain().last_key())
                .field(
                    "other_prefixes",
                    &format_args!("({:b})", network.prefixes().format(", ")),
                )
                .finish(),
            Self::Relocate(payload) => write!(f, "Relocate({:?})", payload),
            Self::RelocatePromise(payload) => write!(f, "RelocatePromise({:?})", payload),
            Self::JoinRequest(payload) => write!(f, "JoinRequest({:?})", payload),
            Self::JoinRetry {
                elders_info,
                section_key,
            } => f
                .debug_struct("JoinRetry")
                .field("elders_info", elders_info)
                .field("section_key", section_key)
                .finish(),
            Self::BouncedUntrustedMessage(message) => f
                .debug_tuple("BouncedUntrustedMessage")
                .field(message)
                .finish(),
            Self::BouncedUnknownMessage { src_key, message } => f
                .debug_struct("BouncedUnknownMessage")
                .field("src_key", src_key)
                .field("message_hash", &MessageHash::from_bytes(message))
                .finish(),
            Self::DkgStart {
                dkg_key,
                elders_info,
            } => f
                .debug_struct("DkgStart")
                .field("dkg_key", dkg_key)
                .field("elders_info", elders_info)
                .finish(),
            Self::DkgMessage { dkg_key, message } => f
                .debug_struct("DkgMessage")
                .field("dkg_key", &dkg_key)
                .field("message", message)
                .finish(),
            Self::DkgFailureObservation { dkg_key, proof } => f
                .debug_struct("DkgFailureObservation")
                .field("dkg_key", dkg_key)
                .field("proof", proof)
                .finish(),
            Self::DkgFailureAgreement(proofs) => {
                f.debug_tuple("DkgFailureAgreement").field(proofs).finish()
            }
            Self::Vote {
                content,
                proof_share,
            } => f
                .debug_struct("Vote")
                .field("content", content)
                .field("proof_share", proof_share)
                .finish(),
            Self::ResourceChallenge {
                data_size,
                difficulty,
                ..
            } => f
                .debug_struct("ResourceChallenge")
                .field("data_size", data_size)
                .field("difficulty", difficulty)
                .finish(),
        }
    }
}

/// Joining peer's proof of resolvement of given resource proofing challenge.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ResourceProofResponse {
    pub(crate) solution: u64,
    pub(crate) data: VecDeque<u8>,
    pub(crate) nonce: [u8; 32],
    pub(crate) nonce_signature: Signature,
}

/// Request to join a section
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct JoinRequest {
    /// The public key of the section to join.
    pub section_key: bls::PublicKey,
    /// If the peer is being relocated, contains `RelocatePayload`. Otherwise contains `None`.
    pub relocate_payload: Option<RelocatePayload>,
    /// Proof of the resouce proofing.
    pub resource_proof_response: Option<ResourceProofResponse>,
}

impl Debug for JoinRequest {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("JoinRequest")
            .field("section_key", &self.section_key)
            .field(
                "relocate_payload",
                &self
                    .relocate_payload
                    .as_ref()
                    .map(|payload| payload.relocate_details()),
            )
            .field(
                "resource_proof_response",
                &self
                    .resource_proof_response
                    .as_ref()
                    .map(|proof| proof.solution),
            )
            .finish()
    }
}
