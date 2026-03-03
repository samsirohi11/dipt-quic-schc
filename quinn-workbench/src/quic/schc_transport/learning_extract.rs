use crate::quic::schc_transport::learning::LearningState;
use schc::field_id::FieldId;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const IPV6_UDP_HEADER_LEN: usize = IPV6_HEADER_LEN + UDP_HEADER_LEN;
const FULL_L2_L4_HEADER_LEN: usize = ETHERNET_HEADER_LEN + IPV6_UDP_HEADER_LEN;

pub(super) fn field_key(fid: FieldId) -> String {
    format!("{fid:?}")
}

pub(super) fn extract_learning_fields(
    packet: &[u8],
    state: &mut LearningState,
) -> Vec<(FieldId, Vec<u8>)> {
    if packet.len() < FULL_L2_L4_HEADER_LEN {
        return Vec::new();
    }

    let ipv6 = &packet[ETHERNET_HEADER_LEN..];
    let mut fields = Vec::with_capacity(27);

    fields.push((FieldId::Ipv6Ver, vec![(ipv6[0] >> 4) & 0x0F]));
    let tc = ((ipv6[0] & 0x0F) << 4) | ((ipv6[1] >> 4) & 0x0F);
    fields.push((FieldId::Ipv6Tc, vec![tc]));
    let fl = ((ipv6[1] as u32 & 0x0F) << 16) | ((ipv6[2] as u32) << 8) | (ipv6[3] as u32);
    fields.push((FieldId::Ipv6Fl, fl.to_be_bytes()[1..4].to_vec()));
    fields.push((FieldId::Ipv6Len, ipv6[4..6].to_vec()));
    fields.push((FieldId::Ipv6Nxt, vec![ipv6[6]]));
    fields.push((FieldId::Ipv6HopLmt, vec![ipv6[7]]));
    fields.push((FieldId::Ipv6Src, ipv6[8..24].to_vec()));
    fields.push((FieldId::Ipv6Dst, ipv6[24..40].to_vec()));
    fields.push((FieldId::Ipv6SrcPrefix, ipv6[8..16].to_vec()));
    fields.push((FieldId::Ipv6SrcIid, ipv6[16..24].to_vec()));
    fields.push((FieldId::Ipv6DstPrefix, ipv6[24..32].to_vec()));
    fields.push((FieldId::Ipv6DstIid, ipv6[32..40].to_vec()));
    fields.push((FieldId::Ipv6DevPrefix, ipv6[8..16].to_vec()));
    fields.push((FieldId::Ipv6DevIid, ipv6[16..24].to_vec()));
    fields.push((FieldId::Ipv6AppPrefix, ipv6[24..32].to_vec()));
    fields.push((FieldId::Ipv6AppIid, ipv6[32..40].to_vec()));

    if ipv6[6] == 17 {
        let udp = &ipv6[IPV6_HEADER_LEN..];
        fields.push((FieldId::UdpSrcPort, udp[0..2].to_vec()));
        fields.push((FieldId::UdpDstPort, udp[2..4].to_vec()));
        fields.push((FieldId::UdpDevPort, udp[0..2].to_vec()));
        fields.push((FieldId::UdpAppPort, udp[2..4].to_vec()));
        fields.push((FieldId::UdpLen, udp[4..6].to_vec()));
        fields.push((FieldId::UdpCksum, udp[6..8].to_vec()));
        fields.extend(extract_quic_learning_fields(&udp[UDP_HEADER_LEN..], state));
    }

    fields
}

fn extract_quic_learning_fields(
    payload: &[u8],
    state: &mut LearningState,
) -> Vec<(FieldId, Vec<u8>)> {
    if payload.is_empty() {
        return Vec::new();
    }

    let mut fields = Vec::with_capacity(6);
    let first_byte = payload[0];
    fields.push((FieldId::QuicFirstByte, vec![first_byte]));

    if (first_byte & 0x80) != 0 {
        if payload.len() < 6 {
            return fields;
        }
        fields.push((FieldId::QuicVersion, payload[1..5].to_vec()));

        let dcid_len = payload[5] as usize;
        let dcid_start = 6usize;
        let dcid_end = dcid_start.saturating_add(dcid_len);
        if payload.len() < dcid_end {
            return fields;
        }

        let dcid = payload[dcid_start..dcid_end].to_vec();
        fields.push((FieldId::QuicDcidLen, vec![dcid_len as u8]));
        fields.push((FieldId::QuicDcid, dcid.clone()));
        state.short_dcid_len = Some(dcid_len);
        state.short_dcid = (!dcid.is_empty()).then_some(dcid);

        if payload.len() <= dcid_end {
            return fields;
        }
        let scid_len = payload[dcid_end] as usize;
        let scid_start = dcid_end + 1;
        let scid_end = scid_start.saturating_add(scid_len);
        if payload.len() < scid_end {
            return fields;
        }
        fields.push((FieldId::QuicScidLen, vec![scid_len as u8]));
        fields.push((FieldId::QuicScid, payload[scid_start..scid_end].to_vec()));
        return fields;
    }

    state.short_packet_count = state.short_packet_count.saturating_add(1);
    if let (Some(dcid_len), Some(short_dcid)) = (state.short_dcid_len, state.short_dcid.as_ref())
        && dcid_len > 0
        && payload.len() > dcid_len
    {
        let candidate = &payload[1..(1 + dcid_len)];
        if candidate == short_dcid.as_slice() {
            // Short headers don't carry DCID length on-wire; only emit the CID value when present.
            fields.push((FieldId::QuicDcid, short_dcid.clone()));
            *state
                .short_cid_counts
                .entry(short_dcid.clone())
                .or_insert(0) += 1;
        }
    }
    fields
}
