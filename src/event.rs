// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bytes::Bytes;
use ed25519_dalek::Keypair;
use hex_fmt::HexFmt;
pub use qp2p::{RecvStream, SendStream};
use sn_messaging::{client::Message, DstLocation, EndUser, SrcLocation};
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    sync::Arc,
};
use xor_name::{Prefix, XorName};

/// A flag in EldersChanged event, indicating
/// whether the node got promoted, demoted or did not change.
#[derive(Debug)]
pub enum NodeElderChange {
    /// The node was promoted to Elder.
    Promoted,
    /// The node was demoted to Adult.
    Demoted,
    /// There was no change to the node.
    None,
}

///
#[derive(Debug, Clone, PartialEq)]
pub struct Elders {
    /// The prefix of the section.
    pub prefix: Prefix,
    /// The BLS public key of a section.
    pub key: bls::PublicKey,
    /// The set of elders of a section.
    pub elders: BTreeSet<XorName>,
}

impl Elders {
    /// The BLS public key
    pub fn key(&self) -> sn_data_types::PublicKey {
        sn_data_types::PublicKey::Bls(self.key)
    }

    /// The BLS based name
    pub fn name(&self) -> XorName {
        self.key().into()
    }

    /// The prefix based address
    pub fn address(&self) -> XorName {
        self.prefix.name()
    }
}

/// An Event raised by a `Node` or `Client` via its event sender.
///
/// These are sent by sn_routing to the library's user. It allows the user to handle requests and
/// responses, and to react to changes in the network.
///
/// `Request` and `Response` events from section locations are only raised once the majority has
/// been reached, i.e. enough members of the section have sent the same message.
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// This is the very first node in a network.
    Genesis,
    /// Received a message.
    MessageReceived {
        /// The content of the message.
        content: Bytes,
        /// The source location that sent the message.
        src: SrcLocation,
        /// The destination location that receives the message.
        dst: DstLocation,
    },
    /// The node has been promoted to adult
    PromotedToAdult,
    /// A new peer joined our section.
    MemberJoined {
        /// Name of the node
        name: XorName,
        /// Previous name before relocation or `None` if it is a new node.
        previous_name: Option<XorName>,
        /// Age of the node
        age: u8,
        /// Indication that is has been relocated during startup.
        startup_relocation: bool,
    },
    /// A node left our section.
    MemberLeft {
        /// Name of the node
        name: XorName,
        /// Age of the node
        age: u8,
    },
    /// The set of elders in our section has changed.
    EldersChanged {
        /// The Elders of our section.
        elders: Elders,
        /// The Elders of the sibling section, if this event is fired during a split.
        /// Otherwise `None`.
        sibling_elders: Option<Elders>,
        /// Promoted, demoted or no change?
        self_status_change: NodeElderChange,
    },
    /// This node has started relocating to other section. Will be followed by
    /// `Relocated` when the node finishes joining the destination section.
    RelocationStarted {
        /// Previous name before relocation
        previous_name: XorName,
    },
    /// This node has completed relocation to other section.
    Relocated {
        /// Old name before the relocation.
        previous_name: XorName,
        /// New keypair to be used after relocation.
        new_keypair: Arc<Keypair>,
    },
    /// Disconnected or failed to connect - restart required.
    RestartRequired,
    /// Received a message from a client node.
    ClientMessageReceived {
        /// The content of the message.
        msg: Box<Message>,
        /// The SocketAddr and PublicKey that sent the message.
        /// (Note: socket_id will be a random hash, to map against the actual socketaddr)
        user: EndUser,
    },
    /// Failed in sending a message to client, or connection to client is lost
    ClientLost(SocketAddr),
}

impl Debug for Event {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Self::Genesis => write!(formatter, "Genesis"),
            Self::MessageReceived { content, src, dst } => write!(
                formatter,
                "MessageReceived {{ content: \"{:<8}\", src: {:?}, dst: {:?} }}",
                HexFmt(content),
                src,
                dst
            ),
            Self::PromotedToAdult => write!(formatter, "PromotedToAdult"),
            Self::MemberJoined {
                name,
                previous_name,
                age,
                startup_relocation,
            } => formatter
                .debug_struct("MemberJoined")
                .field("name", name)
                .field("previous_name", previous_name)
                .field("age", age)
                .field("startup_relocation", startup_relocation)
                .finish(),
            Self::MemberLeft { name, age } => formatter
                .debug_struct("MemberLeft")
                .field("name", name)
                .field("age", age)
                .finish(),
            Self::EldersChanged {
                elders,
                sibling_elders,
                self_status_change,
            } => formatter
                .debug_struct("EldersChanged")
                .field("elders", elders)
                .field("sibling_elders", sibling_elders)
                .field("self_status_change", self_status_change)
                .finish(),
            Self::RelocationStarted { previous_name } => formatter
                .debug_struct("RelocationStarted")
                .field("previous_name", previous_name)
                .finish(),
            Self::Relocated {
                previous_name,
                new_keypair,
            } => formatter
                .debug_struct("Relocated")
                .field("previous_name", previous_name)
                .field("new_keypair", new_keypair)
                .finish(),
            Self::RestartRequired => write!(formatter, "RestartRequired"),
            Self::ClientMessageReceived { msg, user, .. } => write!(
                formatter,
                "ClientMessageReceived {{ msg: {:?}, src: {:?} }}",
                msg, user,
            ),
            Self::ClientLost(addr) => write!(formatter, "ClientLost({:?})", addr),
        }
    }
}
