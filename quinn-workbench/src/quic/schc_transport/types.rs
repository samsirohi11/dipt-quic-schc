use crate::config::cli::SchcLearnerProfile;
use parking_lot::RwLock;
use schc::Direction;
use schc_coreconf::SchcCoreconfManager;
use std::sync::Arc;

pub(super) const FLOW_LABEL: u32 = 0x12345;
pub(super) const TRAFFIC_CLASS: u8 = 0;
pub(super) const HOP_LIMIT: u8 = 64;
pub(super) const SCHC_FRAME_BITLEN_PREFIX_BYTES: usize = 4;
pub(super) const CORECONF_MESSAGE_MAGIC: [u8; 4] = *b"SCCF";
pub(super) const CORECONF_MESSAGE_VERSION: u8 = 1;
pub(super) const CORECONF_MESSAGE_PREFIX_BYTES: usize = 6;

const DEVICE_PREFIX: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00];
const DEVICE_IID: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
const CORE_PREFIX: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00];
const CORE_IID: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];

pub(super) type SharedManager = Arc<RwLock<SchcCoreconfManager>>;

#[derive(Clone, Copy)]
pub(super) enum NodeRole {
    Client,
    Server,
}

impl NodeRole {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            NodeRole::Client => "client",
            NodeRole::Server => "server",
        }
    }

    pub(super) fn outgoing_direction(self) -> Direction {
        match self {
            NodeRole::Client => Direction::Up,
            NodeRole::Server => Direction::Down,
        }
    }

    pub(super) fn incoming_direction(self) -> Direction {
        match self {
            NodeRole::Client => Direction::Down,
            NodeRole::Server => Direction::Up,
        }
    }

    pub(super) fn source_addr_parts(self) -> ([u8; 8], [u8; 8]) {
        match self {
            NodeRole::Client => (DEVICE_PREFIX, DEVICE_IID),
            NodeRole::Server => (CORE_PREFIX, CORE_IID),
        }
    }

    pub(super) fn target_addr_parts(self) -> ([u8; 8], [u8; 8]) {
        match self {
            NodeRole::Client => (CORE_PREFIX, CORE_IID),
            NodeRole::Server => (DEVICE_PREFIX, DEVICE_IID),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct LearnerProfilePolicy {
    pub(super) name: &'static str,
    pub(super) low_risk_min_observations: u32,
    pub(super) low_risk_min_percent: u8,
    pub(super) short_cid_min_packets: u32,
    pub(super) short_cid_min_percent: u8,
}

fn policy(
    name: &'static str,
    low_risk_min_observations: u32,
    low_risk_min_percent: u8,
    short_cid_min_packets: u32,
    short_cid_min_percent: u8,
) -> LearnerProfilePolicy {
    LearnerProfilePolicy {
        name,
        low_risk_min_observations,
        low_risk_min_percent,
        short_cid_min_packets,
        short_cid_min_percent,
    }
}

pub(super) fn profile_policy(profile: SchcLearnerProfile) -> LearnerProfilePolicy {
    match profile {
        SchcLearnerProfile::Fast => policy("fast", 3, 90, 12, 90),
        SchcLearnerProfile::Balanced => policy("balanced", 4, 95, 16, 95),
        SchcLearnerProfile::Strict => policy("strict", 6, 98, 20, 98),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum QuicHeaderKind {
    Long,
    Short,
}
