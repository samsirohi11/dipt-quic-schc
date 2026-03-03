use crate::quic::schc_transport::coreconf::{
    CoreconfMessageType, apply_duplicate_rule_rpc_payload, build_duplicate_rule_modifications,
    encode_coreconf_message, field_target_value_bytes, format_target_bytes_for_display,
};
use crate::quic::schc_transport::learning_extract::{extract_learning_fields, field_key};
use crate::quic::schc_transport::learning_rules::{
    allocate_breadth_first_rule_id, derive_stage_one_rule, derive_stage_two_rule,
    select_stage_one_base_rule,
};
use crate::quic::schc_transport::packet::detect_quic_header_kind;
use crate::quic::schc_transport::types::{LearnerProfilePolicy, QuicHeaderKind, SharedManager};
use parking_lot::RwLock;
use schc::field_id::FieldId;
use schc::rule::Rule;
use schc_coreconf::rpc_builder::{EntryModification, build_duplicate_rule_rpc};
use std::collections::BTreeMap;

pub(super) struct LearningSync {
    profile: LearnerProfilePolicy,
    local: SharedManager,
    peer: SharedManager,
    state: RwLock<LearningState>,
}

#[derive(Default, Clone)]
struct FieldObservation {
    total: u32,
    counts: BTreeMap<Vec<u8>, u32>,
}

impl FieldObservation {
    fn observe(&mut self, value: Vec<u8>) {
        self.total = self.total.saturating_add(1);
        *self.counts.entry(value).or_insert(0) += 1;
    }

    fn dominant(&self) -> Option<(Vec<u8>, u32)> {
        self.counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(value, count)| (value.clone(), *count))
    }
}

#[derive(Default, Clone)]
pub(super) struct LearningState {
    observed_packets: u32,
    pub(super) short_dcid: Option<Vec<u8>>,
    pub(super) short_dcid_len: Option<usize>,
    pub(super) short_packet_count: u32,
    pub(super) short_cid_counts: BTreeMap<Vec<u8>, u32>,
    rule_match_counts: BTreeMap<(u32, u8), u32>,
    short_rule_match_counts: BTreeMap<(u32, u8), u32>,
    field_observations: BTreeMap<String, FieldObservation>,
    stage_one_emitted: bool,
    stage_two_emitted: bool,
    stage_one_rule: Option<(u32, u8)>,
}

impl LearningState {
    fn observe_rule_match(
        &mut self,
        observed_rule: Option<(u32, u8)>,
        quic_kind: Option<QuicHeaderKind>,
    ) {
        if let Some(rule_key) = observed_rule {
            *self.rule_match_counts.entry(rule_key).or_insert(0) += 1;
            if quic_kind == Some(QuicHeaderKind::Short) {
                *self.short_rule_match_counts.entry(rule_key).or_insert(0) += 1;
            }
        }
    }

    fn observe_fields(&mut self, fields: Vec<(FieldId, Vec<u8>)>) {
        for (fid, value) in fields {
            self.field_observations
                .entry(field_key(fid))
                .or_default()
                .observe(value);
        }
    }

    pub(super) fn dominant_field_value(&self, fid: FieldId) -> Option<(Vec<u8>, u32, u32)> {
        let observation = self.field_observations.get(&field_key(fid))?;
        let (value, count) = observation.dominant()?;
        Some((value, count, observation.total))
    }

    pub(super) fn dominant_short_dcid(&self) -> Option<(Vec<u8>, u32)> {
        self.short_cid_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(cid, count)| (cid.clone(), *count))
    }
}

impl LearningSync {
    pub(super) fn new(
        profile: LearnerProfilePolicy,
        local: SharedManager,
        peer: SharedManager,
    ) -> Self {
        Self {
            profile,
            local,
            peer,
            state: RwLock::new(LearningState::default()),
        }
    }

    pub(super) fn observe_and_maybe_apply(&self, packet: &[u8], observed_rule: Option<(u32, u8)>) {
        let quic_kind = detect_quic_header_kind(packet);
        let snapshot = {
            let mut state = self.state.write();
            state.observed_packets = state.observed_packets.saturating_add(1);
            state.observe_rule_match(observed_rule, quic_kind);
            let fields = extract_learning_fields(packet, &mut state);
            state.observe_fields(fields);
            state.clone()
        };

        self.maybe_emit_stage_one(&snapshot);
        self.maybe_emit_stage_two(&snapshot);
    }

    fn active_rules_snapshot(&self) -> Vec<Rule> {
        self.local
            .read()
            .active_rules()
            .iter()
            .copied()
            .cloned()
            .collect::<Vec<_>>()
    }

    fn maybe_emit_stage_one(&self, snapshot: &LearningState) {
        if snapshot.stage_one_emitted {
            return;
        }
        if snapshot.short_packet_count == 0 {
            return;
        }

        let active_rules = self.active_rules_snapshot();
        let Some(base_rule) = select_stage_one_base_rule(
            &active_rules,
            &snapshot.rule_match_counts,
            &snapshot.short_rule_match_counts,
        )
        .or_else(|| active_rules.first().cloned()) else {
            return;
        };

        let Some(mut stage_rule) = derive_stage_one_rule(&base_rule, snapshot, self.profile) else {
            return;
        };

        {
            let mut state = self.state.write();
            if state.stage_one_emitted {
                return;
            }
            state.stage_one_emitted = true;
        }

        let source = (base_rule.rule_id, base_rule.rule_id_length);
        let Some((target_id, target_len)) =
            allocate_breadth_first_rule_id(&self.local.read(), source.1)
        else {
            println!(
                "* schc_device stage-1 skipped: no available rule id at/above length {}",
                source.1
            );
            return;
        };
        stage_rule.rule_id = target_id;
        stage_rule.rule_id_length = target_len;

        let modifications = build_duplicate_rule_modifications(&base_rule, &stage_rule);
        if modifications.is_empty() {
            println!("* schc_device stage-1 skipped: no low-risk stable modifications");
            return;
        }

        print_stage_report(
            "stage-1",
            self.profile.name,
            snapshot,
            source,
            (target_id, target_len),
        );
        print_stage_candidate_updates(&base_rule, &stage_rule);
        if self.synchronize_rule(source, (target_id, target_len), &modifications) {
            self.state.write().stage_one_rule = Some((target_id, target_len));
        }
    }

    fn maybe_emit_stage_two(&self, snapshot: &LearningState) {
        if snapshot.stage_two_emitted {
            return;
        }
        let Some(stage_one_rule_id) = snapshot.stage_one_rule else {
            return;
        };

        let active_rules = self.active_rules_snapshot();
        let Some(stage_one_rule) = active_rules
            .iter()
            .find(|rule| {
                rule.rule_id == stage_one_rule_id.0 && rule.rule_id_length == stage_one_rule_id.1
            })
            .cloned()
        else {
            return;
        };

        let Some(mut stage_two_rule) =
            derive_stage_two_rule(&stage_one_rule, snapshot, self.profile)
        else {
            return;
        };

        {
            let mut state = self.state.write();
            if state.stage_two_emitted {
                return;
            }
            state.stage_two_emitted = true;
        }

        let source = (stage_one_rule.rule_id, stage_one_rule.rule_id_length);
        let Some((target_id, target_len)) =
            allocate_breadth_first_rule_id(&self.local.read(), source.1)
        else {
            println!(
                "* schc_device stage-2 skipped: no available rule id at/above length {}",
                source.1
            );
            return;
        };
        stage_two_rule.rule_id = target_id;
        stage_two_rule.rule_id_length = target_len;

        let modifications = build_duplicate_rule_modifications(&stage_one_rule, &stage_two_rule);
        if modifications.is_empty() {
            println!("* schc_device stage-2 skipped: no CID-specific modification");
            return;
        }

        print_stage_report(
            "stage-2",
            self.profile.name,
            snapshot,
            source,
            (target_id, target_len),
        );
        print_stage_candidate_updates(&stage_one_rule, &stage_two_rule);
        let _ = self.synchronize_rule(source, (target_id, target_len), &modifications);
    }

    fn synchronize_rule(
        &self,
        source: (u32, u8),
        target: (u32, u8),
        modifications: &[EntryModification],
    ) -> bool {
        let rpc_payload = build_duplicate_rule_rpc(source, target, Some(modifications));
        if rpc_payload.is_empty() {
            println!(
                "* schc_device rejected derived rule {}/{} (failed to build duplicate-rule RPC payload)",
                target.0, target.1
            );
            return false;
        }

        let coreconf_message = match encode_coreconf_message(
            CoreconfMessageType::SchcDeviceDuplicateRule,
            &rpc_payload,
        ) {
            Ok(message) => message,
            Err(e) => {
                println!(
                    "* schc_device rejected derived rule {}/{} (failed to encode CORECONF message: {e})",
                    target.0, target.1
                );
                return false;
            }
        };

        let local_result =
            apply_duplicate_rule_rpc_payload(&mut self.local.write(), &coreconf_message);
        let peer_result =
            apply_duplicate_rule_rpc_payload(&mut self.peer.write(), &coreconf_message);
        match (local_result, peer_result) {
            (Ok(()), Ok(())) => {
                println!(
                    "* CORECONF {} synchronized derived rule {}/{} via duplicate-rule {}/{} -> {}/{} (rpc={} bytes, message={} bytes)",
                    CoreconfMessageType::SchcDeviceDuplicateRule.as_str(),
                    target.0,
                    target.1,
                    source.0,
                    source.1,
                    target.0,
                    target.1,
                    rpc_payload.len(),
                    coreconf_message.len()
                );
                true
            }
            (local_err, peer_err) => {
                println!(
                    "* CORECONF {} rejected derived rule {}/{} via duplicate-rule {}/{} -> {}/{} (local: {:?}, peer: {:?})",
                    CoreconfMessageType::SchcDeviceDuplicateRule.as_str(),
                    target.0,
                    target.1,
                    source.0,
                    source.1,
                    target.0,
                    target.1,
                    local_err.as_ref().err(),
                    peer_err.as_ref().err()
                );
                false
            }
        }
    }
}

fn print_stage_report(
    stage_name: &str,
    profile_name: &str,
    state: &LearningState,
    source: (u32, u8),
    target: (u32, u8),
) {
    println!("--- schc_device learning report ---");
    println!("* learner_profile: {profile_name}");
    println!("* observed_packets: {}", state.observed_packets);
    if !state.rule_match_counts.is_empty() {
        println!("* matched_rule_histogram:");
        let mut entries = state
            .rule_match_counts
            .iter()
            .map(|(&(id, len), &count)| {
                let short_count = state
                    .short_rule_match_counts
                    .get(&(id, len))
                    .copied()
                    .unwrap_or(0);
                (count, short_count, id, len)
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| b.cmp(a));
        for (count, short_count, id, len) in entries {
            println!("  - {id}/{len}: matches={count}, short_matches={short_count}");
        }
    }
    println!(
        "* {}: duplicate-rule {}/{} -> {}/{}",
        stage_name, source.0, source.1, target.0, target.1
    );
}

fn print_stage_candidate_updates(base_rule: &Rule, derived_rule: &Rule) {
    println!(
        "* learned_modifications: base rule {}/{}",
        base_rule.rule_id, base_rule.rule_id_length
    );
    let mut updates = 0usize;
    for (index, (before, after)) in base_rule
        .compression
        .iter()
        .zip(derived_rule.compression.iter())
        .enumerate()
    {
        let before_tv = field_target_value_bytes(before);
        let after_tv = field_target_value_bytes(after);
        if before.mo == after.mo && before.cda == after.cda && before_tv == after_tv {
            continue;
        }
        let after_tv_display = after_tv
            .as_deref()
            .map(format_target_bytes_for_display)
            .unwrap_or_else(|| "-".to_string());
        updates += 1;
        println!(
            "  - field[{index}] fid={}: mo {:?} -> {:?}, cda {:?} -> {:?}, tv {}",
            after.fid, before.mo, after.mo, before.cda, after.cda, after_tv_display
        );
    }
    if updates == 0 {
        println!("  - none");
    }
}
