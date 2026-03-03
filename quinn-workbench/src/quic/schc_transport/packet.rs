use crate::quic::schc_transport::types::{
    HOP_LIMIT, QuicHeaderKind, SCHC_FRAME_BITLEN_PREFIX_BYTES,
};
use anyhow::{Context as _, bail};
use schc::Direction;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const IPV6_PROTOCOL_UDP: u8 = 17;
const ETHER_TYPE_IPV6: [u8; 2] = [0x86, 0xdd];

pub(super) fn encode_schc_frame(bit_length: usize, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let bit_length = u32::try_from(bit_length).context("SCHC bit length exceeds u32")?;
    let mut framed = Vec::with_capacity(SCHC_FRAME_BITLEN_PREFIX_BYTES + data.len());
    framed.extend_from_slice(&bit_length.to_be_bytes());
    framed.extend_from_slice(data);
    Ok(framed)
}

pub(super) fn decode_schc_frame(frame: &[u8]) -> anyhow::Result<(&[u8], usize)> {
    if frame.len() < SCHC_FRAME_BITLEN_PREFIX_BYTES {
        bail!(
            "invalid SCHC frame: {} bytes (expected at least {} bytes)",
            frame.len(),
            SCHC_FRAME_BITLEN_PREFIX_BYTES
        );
    }

    let bit_length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    let compressed = &frame[SCHC_FRAME_BITLEN_PREFIX_BYTES..];
    if bit_length > compressed.len() * 8 {
        bail!(
            "invalid SCHC frame bit length {bit_length} (payload only has {} bits)",
            compressed.len() * 8
        );
    }
    Ok((compressed, bit_length))
}

pub(super) fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Up => "up",
        Direction::Down => "down",
    }
}

pub(super) fn extract_udp_payload(packet: &[u8]) -> anyhow::Result<&[u8]> {
    if packet.len() >= 62 && packet[12..14] == ETHER_TYPE_IPV6 {
        let payload_start = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN;
        if packet.len() < payload_start {
            bail!("invalid decompressed packet with ethernet header");
        }
        return Ok(&packet[payload_start..]);
    }

    if packet.len() < 48 {
        bail!("invalid decompressed packet length {}", packet.len());
    }

    Ok(&packet[48..])
}

pub(super) fn detect_quic_header_kind(packet: &[u8]) -> Option<QuicHeaderKind> {
    if packet.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + 1 {
        return None;
    }
    let ipv6 = &packet[ETHERNET_HEADER_LEN..];
    if ipv6[6] != IPV6_PROTOCOL_UDP {
        return None;
    }
    let first_byte = ipv6[IPV6_HEADER_LEN + UDP_HEADER_LEN];
    if (first_byte & 0x80) != 0 {
        Some(QuicHeaderKind::Long)
    } else {
        Some(QuicHeaderKind::Short)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_ipv6_udp_packet(
    src_prefix: &[u8; 8],
    src_iid: &[u8; 8],
    dst_prefix: &[u8; 8],
    dst_iid: &[u8; 8],
    src_port: u16,
    dst_port: u16,
    traffic_class: u8,
    flow_label: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet =
        Vec::with_capacity(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload.len());

    // Ethernet header
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x86, 0xDD,
    ]);

    // IPv6 header
    let version_tc_fl = (6u32 << 28) | ((traffic_class as u32) << 20) | (flow_label & 0xFFFFF);
    packet.extend_from_slice(&version_tc_fl.to_be_bytes());
    let payload_length = (8 + payload.len()) as u16;
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.push(17); // UDP
    packet.push(HOP_LIMIT);
    packet.extend_from_slice(src_prefix);
    packet.extend_from_slice(src_iid);
    packet.extend_from_slice(dst_prefix);
    packet.extend_from_slice(dst_iid);

    // UDP header
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // checksum not required in simulation mode

    packet.extend_from_slice(payload);
    packet
}
