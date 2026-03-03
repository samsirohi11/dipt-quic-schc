use crate::quic::schc_transport::learning::LearningState;
use crate::quic::schc_transport::types::LearnerProfilePolicy;
use schc::Rule;
use schc::field_id::{FieldId, Protocol};
use schc::rule::{CompressionAction, MatchingOperator, ParsedTargetValue, RuleValue};
use schc_coreconf::SchcCoreconfManager;
use std::collections::{BTreeMap, HashSet};

pub(super) fn derive_stage_one_rule(
    base_rule: &Rule,
    state: &LearningState,
    profile: LearnerProfilePolicy,
) -> Option<Rule> {
    let mut derived = base_rule.clone();
    for field in &mut derived.compression {
        if !is_stage_one_eligible_field(field) {
            continue;
        }
        let Some((value, dominant_count, total_count)) = state.dominant_field_value(field.fid)
        else {
            continue;
        };
        if !field_meets_threshold(
            dominant_count,
            total_count,
            profile.low_risk_min_observations,
            profile.low_risk_min_percent,
        ) {
            continue;
        }
        apply_field_constant_specialization(field, &value);
    }

    let modifications = super::coreconf::build_duplicate_rule_modifications(base_rule, &derived);
    (!modifications.is_empty()).then_some(derived)
}

pub(super) fn derive_stage_two_rule(
    stage_one_rule: &Rule,
    state: &LearningState,
    profile: LearnerProfilePolicy,
) -> Option<Rule> {
    if !rule_looks_like_quic_short_header(stage_one_rule) {
        return None;
    }
    let Some((dominant_cid, dominant_count)) = state.dominant_short_dcid() else {
        return None;
    };
    if !field_meets_threshold(
        dominant_count,
        state.short_packet_count,
        profile.short_cid_min_packets,
        profile.short_cid_min_percent,
    ) {
        return None;
    }

    let mut derived = stage_one_rule.clone();
    let Some(dcid_field) = derived
        .compression
        .iter_mut()
        .find(|field| field.fid == FieldId::QuicDcid)
    else {
        return None;
    };
    apply_field_constant_specialization(dcid_field, &dominant_cid);

    let modifications =
        super::coreconf::build_duplicate_rule_modifications(stage_one_rule, &derived);
    (!modifications.is_empty()).then_some(derived)
}

pub(super) fn allocate_breadth_first_rule_id(
    manager: &SchcCoreconfManager,
    preferred_min_len: u8,
) -> Option<(u32, u8)> {
    let known = manager.known_rule_ids();
    for len in preferred_min_len..=32 {
        if let Some(id) = first_available_rule_id(known, len) {
            return Some((id, len));
        }
    }
    None
}

pub(super) fn select_stage_one_base_rule(
    active_rules: &[Rule],
    rule_match_counts: &BTreeMap<(u32, u8), u32>,
    short_rule_match_counts: &BTreeMap<(u32, u8), u32>,
) -> Option<Rule> {
    let requires_short_match = active_rules
        .iter()
        .any(|rule| rule_match_count(rule, short_rule_match_counts) > 0);
    let mut candidates = active_rules
        .iter()
        .filter(|rule| {
            !requires_short_match || rule_match_count(rule, short_rule_match_counts) > 0
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        compare_stage_one_base_rule_candidates(a, b, rule_match_counts, short_rule_match_counts)
            .reverse()
    });
    candidates.first().copied().cloned()
}

pub(super) fn rule_has_quic_fields(rule: &Rule) -> bool {
    rule.compression
        .iter()
        .any(|field| is_quic_field(field.fid))
}

fn apply_field_constant_specialization(field: &mut schc::rule::Field, value: &[u8]) {
    field.mo = MatchingOperator::Equal;
    field.cda = CompressionAction::NotSent;
    field.mo_val = None;
    field.tv = None;
    field.parsed_tv = Some(ParsedTargetValue::Single(RuleValue::Bytes(value.to_vec())));
}

fn is_stage_one_eligible_field(field: &schc::rule::Field) -> bool {
    is_stage_one_protocol_field(field.fid)
        && !is_computed_stage_one_field(field.fid)
        && !field_has_existing_tv(field)
}

fn is_stage_one_protocol_field(fid: FieldId) -> bool {
    matches!(fid.protocol(), Protocol::Ipv6 | Protocol::Udp)
}

fn is_computed_stage_one_field(fid: FieldId) -> bool {
    matches!(fid, FieldId::Ipv6Len | FieldId::UdpLen | FieldId::UdpCksum)
}

fn field_has_existing_tv(field: &schc::rule::Field) -> bool {
    field.tv.is_some() || field.parsed_tv.is_some()
}

fn field_meets_threshold(
    dominant_count: u32,
    total_count: u32,
    min_observations: u32,
    min_percent: u8,
) -> bool {
    if total_count < min_observations || total_count == 0 {
        return false;
    }
    dominant_count.saturating_mul(100) >= total_count.saturating_mul(min_percent as u32)
}

fn first_available_rule_id(known: &HashSet<(u32, u8)>, rule_len: u8) -> Option<u32> {
    let mut used = known
        .iter()
        .filter_map(|&(rule_id, len)| (len == rule_len).then_some(rule_id))
        .collect::<Vec<_>>();
    used.sort_unstable();
    used.dedup();

    let max_id = if rule_len == 32 {
        u32::MAX
    } else {
        (1u32 << rule_len) - 1
    };

    let mut candidate = 0u32;
    for used_id in used {
        if used_id == candidate {
            if candidate == u32::MAX {
                return None;
            }
            candidate = candidate.saturating_add(1);
        } else if used_id > candidate {
            break;
        }
    }

    (candidate <= max_id).then_some(candidate)
}

fn rule_looks_like_quic_short_header(rule: &Rule) -> bool {
    let has_short_dcid = rule
        .compression
        .iter()
        .any(|field| field.fid == FieldId::QuicDcid);
    let has_long_header_only_fields = rule.compression.iter().any(|field| {
        matches!(
            field.fid,
            FieldId::QuicVersion | FieldId::QuicDcidLen | FieldId::QuicScidLen | FieldId::QuicScid
        )
    });
    has_short_dcid && !has_long_header_only_fields
}

fn is_quic_field(fid: FieldId) -> bool {
    matches!(
        fid,
        FieldId::QuicFirstByte
            | FieldId::QuicVersion
            | FieldId::QuicDcidLen
            | FieldId::QuicDcid
            | FieldId::QuicScidLen
            | FieldId::QuicScid
    )
}

fn compare_stage_one_base_rule_candidates(
    a: &Rule,
    b: &Rule,
    rule_match_counts: &BTreeMap<(u32, u8), u32>,
    short_rule_match_counts: &BTreeMap<(u32, u8), u32>,
) -> std::cmp::Ordering {
    let a_short_count = rule_match_count(a, short_rule_match_counts);
    let b_short_count = rule_match_count(b, short_rule_match_counts);
    let a_match_count = rule_match_count(a, rule_match_counts);
    let b_match_count = rule_match_count(b, rule_match_counts);
    a_short_count
        .cmp(&b_short_count)
        .then_with(|| a_match_count.cmp(&b_match_count))
        .then_with(|| a.compression.len().cmp(&b.compression.len()))
        .then_with(|| a.rule_id_length.cmp(&b.rule_id_length))
        .then_with(|| a.rule_id.cmp(&b.rule_id))
}

fn rule_match_count(rule: &Rule, counts: &BTreeMap<(u32, u8), u32>) -> u32 {
    counts
        .get(&(rule.rule_id, rule.rule_id_length))
        .copied()
        .unwrap_or(0)
}
