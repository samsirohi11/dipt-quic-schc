use crate::config::cli::{QuicOpt, SchcLearnerProfile};
use anyhow::{Context as _, anyhow, bail};
use base64::Engine;
use in_memory_network::quinn_interop::InMemoryUdpSocket;
use parking_lot::RwLock;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rust_coreconf::SidFile;
use schc::field_id::{FieldId, Protocol};
use schc::rule::{CompressionAction, MatchingOperator, ParsedTargetValue, RuleValue};
use schc::{
    Direction, Rule, build_tree, compress_packet, decompress_packet_with_bit_length, match_rule_id,
};
use schc_coreconf::rpc_builder::{
    EntryModification, build_duplicate_rule_rpc, parse_duplicate_rule_rpc,
};
use schc_coreconf::{MRuleSet, SchcCoreconfManager, cda_to_sid, load_sor_rules, mo_to_sid};
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

const FLOW_LABEL: u32 = 0x12345;
const TRAFFIC_CLASS: u8 = 0;
const HOP_LIMIT: u8 = 64;
const SCHC_FRAME_BITLEN_PREFIX_BYTES: usize = 4;
const CORECONF_MESSAGE_MAGIC: [u8; 4] = *b"SCCF";
const CORECONF_MESSAGE_VERSION: u8 = 1;
const CORECONF_MESSAGE_PREFIX_BYTES: usize = 6;

const DEVICE_PREFIX: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00];
const DEVICE_IID: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
const CORE_PREFIX: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00];
const CORE_IID: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];

type SharedManager = Arc<RwLock<SchcCoreconfManager>>;

#[derive(Clone, Copy, Debug)]
enum CoreconfMessageType {
    SchcDeviceDuplicateRule = 1,
}

impl CoreconfMessageType {
    fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::SchcDeviceDuplicateRule),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::SchcDeviceDuplicateRule => "schc_device->schc_core.duplicate-rule",
        }
    }
}

#[derive(Clone, Copy)]
enum NodeRole {
    Client,
    Server,
}

impl NodeRole {
    fn as_str(self) -> &'static str {
        match self {
            NodeRole::Client => "client",
            NodeRole::Server => "server",
        }
    }

    fn outgoing_direction(self) -> Direction {
        match self {
            NodeRole::Client => Direction::Up,
            NodeRole::Server => Direction::Down,
        }
    }

    fn incoming_direction(self) -> Direction {
        match self {
            NodeRole::Client => Direction::Down,
            NodeRole::Server => Direction::Up,
        }
    }

    fn source_addr_parts(self) -> ([u8; 8], [u8; 8]) {
        match self {
            NodeRole::Client => (DEVICE_PREFIX, DEVICE_IID),
            NodeRole::Server => (CORE_PREFIX, CORE_IID),
        }
    }

    fn target_addr_parts(self) -> ([u8; 8], [u8; 8]) {
        match self {
            NodeRole::Client => (CORE_PREFIX, CORE_IID),
            NodeRole::Server => (DEVICE_PREFIX, DEVICE_IID),
        }
    }
}

#[derive(Debug, Default)]
pub struct SchcTransportStats {
    compressed_sends: AtomicU64,
    passthrough_sends: AtomicU64,
    decompressed_receives: AtomicU64,
    compress_failures: AtomicU64,
    decompress_failures: AtomicU64,
    original_send_bytes: AtomicU64,
    schc_send_bytes: AtomicU64,
    original_receive_bytes: AtomicU64,
    schc_receive_bytes: AtomicU64,
    compressed_by_rule: RwLock<BTreeMap<(u32, u8), u64>>,
}

#[derive(Debug, Clone, Default)]
pub struct SchcTransportStatsSnapshot {
    pub compressed_sends: u64,
    pub passthrough_sends: u64,
    pub decompressed_receives: u64,
    pub compress_failures: u64,
    pub decompress_failures: u64,
    pub original_send_bytes: u64,
    pub schc_send_bytes: u64,
    pub original_receive_bytes: u64,
    pub schc_receive_bytes: u64,
    pub compressed_by_rule: Vec<((u32, u8), u64)>,
}

impl SchcTransportStats {
    fn record_compressed_send(&self, original_bytes: usize, schc_bytes: usize, rule: (u32, u8)) {
        self.compressed_sends.fetch_add(1, Ordering::Relaxed);
        self.original_send_bytes
            .fetch_add(original_bytes as u64, Ordering::Relaxed);
        self.schc_send_bytes
            .fetch_add(schc_bytes as u64, Ordering::Relaxed);
        let mut by_rule = self.compressed_by_rule.write();
        *by_rule.entry(rule).or_insert(0) += 1;
    }

    fn record_decompressed_receive(&self, original_bytes: usize, schc_bytes: usize) {
        self.decompressed_receives.fetch_add(1, Ordering::Relaxed);
        self.original_receive_bytes
            .fetch_add(original_bytes as u64, Ordering::Relaxed);
        self.schc_receive_bytes
            .fetch_add(schc_bytes as u64, Ordering::Relaxed);
    }

    fn record_compress_failure(&self) {
        self.compress_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn record_decompress_failure(&self) {
        self.decompress_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> SchcTransportStatsSnapshot {
        let mut compressed_by_rule = self
            .compressed_by_rule
            .read()
            .iter()
            .map(|(&(id, len), &count)| ((id, len), count))
            .collect::<Vec<_>>();
        compressed_by_rule.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        SchcTransportStatsSnapshot {
            compressed_sends: self.compressed_sends.load(Ordering::Relaxed),
            passthrough_sends: self.passthrough_sends.load(Ordering::Relaxed),
            decompressed_receives: self.decompressed_receives.load(Ordering::Relaxed),
            compress_failures: self.compress_failures.load(Ordering::Relaxed),
            decompress_failures: self.decompress_failures.load(Ordering::Relaxed),
            original_send_bytes: self.original_send_bytes.load(Ordering::Relaxed),
            schc_send_bytes: self.schc_send_bytes.load(Ordering::Relaxed),
            original_receive_bytes: self.original_receive_bytes.load(Ordering::Relaxed),
            schc_receive_bytes: self.schc_receive_bytes.load(Ordering::Relaxed),
            compressed_by_rule,
        }
    }
}

pub fn print_summary(stats: &SchcTransportStats) {
    let snapshot = stats.snapshot();
    let tx_saved = snapshot.original_send_bytes as i64 - snapshot.schc_send_bytes as i64;
    let rx_saved = snapshot.original_receive_bytes as i64 - snapshot.schc_receive_bytes as i64;
    let tx_ratio = percent_saved(snapshot.original_send_bytes, snapshot.schc_send_bytes);
    let rx_ratio = percent_saved(snapshot.original_receive_bytes, snapshot.schc_receive_bytes);

    println!("--- SCHC summary ---");
    println!(
        "* Tx packets: compressed={}, passthrough={}, compress failures={}",
        snapshot.compressed_sends, snapshot.passthrough_sends, snapshot.compress_failures
    );
    println!(
        "* Tx header bytes: original={}, schc={}, saved={} ({tx_ratio:.2}%)",
        snapshot.original_send_bytes, snapshot.schc_send_bytes, tx_saved
    );
    println!(
        "* Rx packets: decompressed={}, decompress failures={}",
        snapshot.decompressed_receives, snapshot.decompress_failures
    );
    println!(
        "* Rx header bytes: original={}, schc={}, saved={} ({rx_ratio:.2}%)",
        snapshot.original_receive_bytes, snapshot.schc_receive_bytes, rx_saved
    );
    println!(
        "* Note: savings are based on parsed fields and may exclude Version-Specific Data and other QUIC header fields."
    );
    if !snapshot.compressed_by_rule.is_empty() {
        println!("* Rule usage:");
        for ((rule_id, rule_len), count) in snapshot.compressed_by_rule {
            println!("  - {rule_id}/{rule_len}: compressed={count}");
        }
    }
}

fn percent_saved(original: u64, schc: u64) -> f64 {
    if original == 0 {
        0.0
    } else {
        ((original as f64 - schc as f64) * 100.0) / original as f64
    }
}

pub fn socket_pair_for_quic(
    quic_opt: &QuicOpt,
    client_socket: InMemoryUdpSocket,
    server_socket: InMemoryUdpSocket,
) -> anyhow::Result<(
    Arc<dyn AsyncUdpSocket>,
    Arc<dyn AsyncUdpSocket>,
    Option<Arc<SchcTransportStats>>,
)> {
    if !quic_opt.schc_enabled {
        return Ok((Arc::new(client_socket), Arc::new(server_socket), None));
    }

    let sid_path = path_option(&quic_opt.schc_sid_file, "--schc-sid-file")?;
    let m_rules_path = path_option(&quic_opt.schc_m_rules, "--schc-m-rules")?;
    let app_rules_path = path_option(&quic_opt.schc_app_rules, "--schc-app-rules")?;

    let sid_file = SidFile::from_file(sid_path)
        .with_context(|| format!("failed loading SID file `{sid_path}`"))?;
    let m_rules = MRuleSet::from_sor(m_rules_path, &sid_file)
        .with_context(|| format!("failed loading M-Rules `{m_rules_path}`"))?;
    let app_rules = load_sor_rules(app_rules_path, &sid_file)
        .with_context(|| format!("failed loading SCHC app rules `{app_rules_path}`"))?;
    let estimated_rtt = Duration::from_millis(quic_opt.schc_estimated_rtt_ms);

    let client_manager = Arc::new(RwLock::new(SchcCoreconfManager::new(
        m_rules.clone(),
        app_rules.clone(),
        estimated_rtt,
    )));
    let server_manager = Arc::new(RwLock::new(SchcCoreconfManager::new(
        m_rules,
        app_rules,
        estimated_rtt,
    )));

    let learning = quic_opt.schc_learner_profile.map(|profile| {
        Arc::new(LearningSync::new(
            profile_policy(profile),
            client_manager.clone(),
            server_manager.clone(),
        ))
    });

    println!("--- SCHC over QUIC transport ---");
    println!("* Enabled QUIC SCHC mode");
    if quic_opt.schc_verbose {
        println!("* Verbose packet tracing enabled");
    }
    if let Some(profile) = quic_opt.schc_learner_profile {
        println!(
            "* Rule learning sync enabled with {} profile",
            profile_policy(profile).name
        );
    }

    let stats = Arc::new(SchcTransportStats::default());
    let client = Arc::new(SchcUdpSocket::new(
        client_socket,
        NodeRole::Client,
        client_manager,
        learning,
        quic_opt.schc_verbose,
        stats.clone(),
    ));
    let server = Arc::new(SchcUdpSocket::new(
        server_socket,
        NodeRole::Server,
        server_manager,
        None,
        quic_opt.schc_verbose,
        stats.clone(),
    ));

    Ok((client, server, Some(stats)))
}

fn path_option<'a>(value: &'a Option<std::path::PathBuf>, arg: &str) -> anyhow::Result<&'a str> {
    let Some(path) = value else {
        bail!("missing required option {arg} when SCHC mode is enabled");
    };
    path.to_str()
        .with_context(|| format!("option {arg} has non-utf8 path: {}", path.display()))
}

#[derive(Clone, Copy)]
struct LearnerProfilePolicy {
    name: &'static str,
    low_risk_min_observations: u32,
    low_risk_min_percent: u8,
    short_cid_min_packets: u32,
    short_cid_min_percent: u8,
}

fn profile_policy(profile: SchcLearnerProfile) -> LearnerProfilePolicy {
    match profile {
        SchcLearnerProfile::Fast => LearnerProfilePolicy {
            name: "fast",
            low_risk_min_observations: 3,
            low_risk_min_percent: 90,
            short_cid_min_packets: 12,
            short_cid_min_percent: 90,
        },
        SchcLearnerProfile::Balanced => LearnerProfilePolicy {
            name: "balanced",
            low_risk_min_observations: 4,
            low_risk_min_percent: 95,
            short_cid_min_packets: 16,
            short_cid_min_percent: 95,
        },
        SchcLearnerProfile::Strict => LearnerProfilePolicy {
            name: "strict",
            low_risk_min_observations: 6,
            low_risk_min_percent: 98,
            short_cid_min_packets: 20,
            short_cid_min_percent: 98,
        },
    }
}

struct LearningSync {
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
struct LearningState {
    observed_packets: u32,
    short_dcid: Option<Vec<u8>>,
    short_dcid_len: Option<usize>,
    short_packet_count: u32,
    short_cid_counts: BTreeMap<Vec<u8>, u32>,
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

    fn dominant_field_value(&self, fid: FieldId) -> Option<(Vec<u8>, u32, u32)> {
        let observation = self.field_observations.get(&field_key(fid))?;
        let (value, count) = observation.dominant()?;
        Some((value, count, observation.total))
    }

    fn dominant_short_dcid(&self) -> Option<(Vec<u8>, u32)> {
        self.short_cid_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(cid, count)| (cid.clone(), *count))
    }
}

fn field_key(fid: FieldId) -> String {
    format!("{fid:?}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuicHeaderKind {
    Long,
    Short,
}

impl LearningSync {
    fn new(profile: LearnerProfilePolicy, local: SharedManager, peer: SharedManager) -> Self {
        Self {
            profile,
            local,
            peer,
            state: RwLock::new(LearningState::default()),
        }
    }

    fn observe_and_maybe_apply(&self, packet: &[u8], observed_rule: Option<(u32, u8)>) {
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

    fn maybe_emit_stage_one(&self, snapshot: &LearningState) {
        if snapshot.stage_one_emitted {
            return;
        }
        if snapshot.short_packet_count == 0 {
            return;
        }

        let active_rules = self
            .local
            .read()
            .active_rules()
            .iter()
            .copied()
            .cloned()
            .collect::<Vec<_>>();
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

        let active_rules = self
            .local
            .read()
            .active_rules()
            .iter()
            .copied()
            .cloned()
            .collect::<Vec<_>>();
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

fn derive_stage_one_rule(
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

    let modifications = build_duplicate_rule_modifications(base_rule, &derived);
    (!modifications.is_empty()).then_some(derived)
}

fn derive_stage_two_rule(
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

    let modifications = build_duplicate_rule_modifications(stage_one_rule, &derived);
    (!modifications.is_empty()).then_some(derived)
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

fn allocate_breadth_first_rule_id(
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

fn build_duplicate_rule_modifications(
    base_rule: &Rule,
    suggested_rule: &Rule,
) -> Vec<EntryModification> {
    let mut modifications = Vec::new();
    for (index, (before, after)) in base_rule
        .compression
        .iter()
        .zip(suggested_rule.compression.iter())
        .enumerate()
    {
        let before_tv = field_target_value_bytes(before);
        let after_tv = field_target_value_bytes(after);
        if before.mo == after.mo && before.cda == after.cda && before_tv == after_tv {
            continue;
        }

        let Ok(entry_index) = u16::try_from(index) else {
            continue;
        };
        let mut modification = EntryModification::new(entry_index);
        if before.mo != after.mo {
            modification = modification.with_mo(mo_to_sid(&after.mo));
        }
        if before.cda != after.cda {
            modification = modification.with_cda(cda_to_sid(&after.cda));
        }
        if before_tv != after_tv
            && let Some(target_bytes) = after_tv
        {
            modification = modification.with_target_value_bytes(target_bytes);
        }
        modifications.push(modification);
    }
    modifications
}

fn field_target_value_bytes(field: &schc::rule::Field) -> Option<Vec<u8>> {
    let parsed = field.parsed_tv.as_ref()?;
    match parsed {
        ParsedTargetValue::Single(value) => Some(rule_value_to_bytes(value)),
        ParsedTargetValue::Mapping(values) => values.first().map(rule_value_to_bytes),
    }
}

fn rule_value_to_bytes(value: &RuleValue) -> Vec<u8> {
    match value {
        RuleValue::U64(n) => u64_to_minimal_be(*n),
        RuleValue::Bytes(bytes) => bytes.clone(),
        RuleValue::String(s) => s.as_bytes().to_vec(),
    }
}

fn u64_to_minimal_be(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let bytes = value.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    bytes[first_non_zero..].to_vec()
}

fn format_target_bytes_for_display(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0x".to_string();
    }
    let mut output = String::from("0x");
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn apply_duplicate_rule_rpc_payload(
    manager: &mut SchcCoreconfManager,
    message: &[u8],
) -> anyhow::Result<()> {
    let (message_type, payload) = decode_coreconf_message(message)?;
    match message_type {
        CoreconfMessageType::SchcDeviceDuplicateRule => {}
    }
    let request = parse_duplicate_rule_rpc(payload)
        .map_err(|e| anyhow!("failed to parse duplicate-rule RPC payload: {e}"))?;
    let modifications = duplicate_modifications_to_json(&request.modifications);
    manager
        .duplicate_rule(request.source, request.target, modifications.as_ref())
        .map_err(|e| anyhow!("failed to apply duplicate-rule RPC: {e}"))?;
    Ok(())
}

fn duplicate_modifications_to_json(
    modifications: &[EntryModification],
) -> Option<serde_json::Value> {
    if modifications.is_empty() {
        return None;
    }

    let entries = modifications
        .iter()
        .map(|m| {
            let mut entry = serde_json::Map::new();
            entry.insert(
                "entry-index".to_string(),
                serde_json::Value::Number((m.entry_index as u64).into()),
            );
            if let Some(mo) = m.matching_operator {
                entry.insert(
                    "matching-operator-sid".to_string(),
                    serde_json::Value::Number(mo.into()),
                );
            }
            if let Some(cda) = m.comp_decomp_action {
                entry.insert(
                    "comp-decomp-action-sid".to_string(),
                    serde_json::Value::Number(cda.into()),
                );
            }
            if let Some(ref target_bytes) = m.target_value {
                entry.insert(
                    "target-value-bytes".to_string(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(target_bytes),
                    ),
                );
            }
            serde_json::Value::Object(entry)
        })
        .collect::<Vec<_>>();

    Some(serde_json::json!({ "entry": entries }))
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

fn rule_has_quic_fields(rule: &Rule) -> bool {
    rule.compression
        .iter()
        .any(|field| is_quic_field(field.fid))
}

fn select_stage_one_base_rule(
    active_rules: &[Rule],
    rule_match_counts: &BTreeMap<(u32, u8), u32>,
    short_rule_match_counts: &BTreeMap<(u32, u8), u32>,
) -> Option<Rule> {
    let has_observed_short_matches = active_rules
        .iter()
        .any(|rule| rule_match_count(rule, short_rule_match_counts) > 0);
    let mut candidates = active_rules
        .iter()
        .filter(|rule| {
            !has_observed_short_matches || rule_match_count(rule, short_rule_match_counts) > 0
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        compare_stage_one_base_rule_candidates(a, b, rule_match_counts, short_rule_match_counts)
            .reverse()
    });
    candidates.first().copied().cloned()
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

fn detect_quic_header_kind(packet: &[u8]) -> Option<QuicHeaderKind> {
    if packet.len() < 14 + 40 + 8 + 1 {
        return None;
    }
    let ipv6 = &packet[14..];
    if ipv6[6] != 17 {
        return None;
    }
    let first_byte = ipv6[48];
    if (first_byte & 0x80) != 0 {
        Some(QuicHeaderKind::Long)
    } else {
        Some(QuicHeaderKind::Short)
    }
}

#[derive(Debug)]
struct AlwaysWritablePoller;

impl UdpPoller for AlwaysWritablePoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct SchcUdpSocket {
    inner: InMemoryUdpSocket,
    role: NodeRole,
    manager: SharedManager,
    learning: Option<Arc<LearningSync>>,
    verbose: bool,
    stats: Arc<SchcTransportStats>,
}

impl Debug for SchcUdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SchcUdpSocket")
    }
}

impl SchcUdpSocket {
    fn new(
        inner: InMemoryUdpSocket,
        role: NodeRole,
        manager: SharedManager,
        learning: Option<Arc<LearningSync>>,
        verbose: bool,
        stats: Arc<SchcTransportStats>,
    ) -> Self {
        Self {
            inner,
            role,
            manager,
            learning,
            verbose,
            stats,
        }
    }

    fn current_rules(&self) -> anyhow::Result<Vec<Rule>> {
        let manager = self.manager.read();
        let ruleset = manager
            .compression_ruleset()
            .context("failed to build SCHC ruleset")?;
        Ok(ruleset.rules.to_vec())
    }

    fn trace_match_stage(
        &self,
        action: &str,
        direction: Direction,
        packet_bytes: usize,
        context: &str,
    ) {
        let node = self
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        println!(
            "* SCHC {action}: node={node}, role={}, direction={}, size={} bytes, {context}",
            self.role.as_str(),
            direction_name(direction),
            packet_bytes
        );
    }

    fn trace_match_result(
        &self,
        action: &str,
        direction: Direction,
        rule: Option<(u32, u8)>,
        packet_bytes: usize,
        context: Option<&str>,
    ) {
        let node = self
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        let rule = rule
            .map(|(id, len)| format!("{id}/{len}"))
            .unwrap_or_else(|| "no-match".to_string());
        match context {
            Some(context) => println!(
                "* SCHC {action}: node={node}, role={}, direction={}, matched={}, size={} bytes, {context}",
                self.role.as_str(),
                direction_name(direction),
                rule,
                packet_bytes
            ),
            None => println!(
                "* SCHC {action}: node={node}, role={}, direction={}, matched={}, size={} bytes",
                self.role.as_str(),
                direction_name(direction),
                rule,
                packet_bytes
            ),
        }
    }

    fn trace_packet(
        &self,
        action: &str,
        direction: Direction,
        rule: Option<(u32, u8)>,
        before_bytes: usize,
        after_bytes: usize,
    ) {
        let node = self
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        let rule = rule
            .map(|(id, len)| format!("{id}/{len}"))
            .unwrap_or_else(|| "no-match".to_string());
        println!(
            "* SCHC {action}: node={node}, role={}, direction={}, rule={}, size={} -> {} bytes",
            self.role.as_str(),
            direction_name(direction),
            rule,
            before_bytes,
            after_bytes
        );
    }
}

impl AsyncUdpSocket for SchcUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritablePoller)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let src_port = self.local_addr()?.port();
        let dst_port = transmit.destination.port();
        let direction = self.role.outgoing_direction();
        let (src_prefix, src_iid) = self.role.source_addr_parts();
        let (dst_prefix, dst_iid) = self.role.target_addr_parts();

        let packet = build_ipv6_udp_packet(
            &src_prefix,
            &src_iid,
            &dst_prefix,
            &dst_iid,
            src_port,
            dst_port,
            TRAFFIC_CLASS,
            FLOW_LABEL,
            transmit.contents,
        );

        let rules = self.current_rules().map_err(io_error)?;
        self.trace_match_stage(
            "compress-pre",
            direction,
            packet.len(),
            &format!("rules={}", rules.len()),
        );
        let tree = build_tree(&rules);
        let compressed = match compress_packet(&tree, &packet, direction, &rules, self.verbose) {
            Ok(compressed) => {
                self.trace_match_result(
                    "compress-match",
                    direction,
                    Some((compressed.rule_id, compressed.rule_id_length)),
                    packet.len(),
                    Some("result=ok"),
                );
                compressed
            }
            Err(e) => {
                self.stats.record_compress_failure();
                let context = format!("result=err, reason={e:?}");
                self.trace_match_result(
                    "compress-match",
                    direction,
                    None,
                    packet.len(),
                    Some(&context),
                );
                self.trace_packet("compress-fail", direction, None, packet.len(), 0);
                return Err(io_error(anyhow!(
                    "failed to compress QUIC datagram with SCHC: {e:?}"
                )));
            }
        };
        let selected_rule_has_quic = rules
            .iter()
            .find(|r| {
                r.rule_id == compressed.rule_id && r.rule_id_length == compressed.rule_id_length
            })
            .is_some_and(rule_has_quic_fields);
        if selected_rule_has_quic && (compressed.compressed_header_bits % 8 != 0) {
            println!(
                "* SCHC compress-note: using QUIC rule {}/{} with non-byte-aligned residue ({} bits) via SCHC bit-length framing",
                compressed.rule_id, compressed.rule_id_length, compressed.compressed_header_bits
            );
        }
        let observed_rule = Some((compressed.rule_id, compressed.rule_id_length));
        if let Some(learning) = &self.learning {
            learning.observe_and_maybe_apply(&packet, observed_rule);
        }
        let framed =
            encode_schc_frame(compressed.bit_length, &compressed.data).map_err(io_error)?;

        let result = self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &framed,
            segment_size: None,
            src_ip: transmit.src_ip,
        });
        if result.is_ok() {
            let original_header_bytes = compressed.original_header_bits.div_ceil(8);
            let schc_header_bytes = compressed.compressed_header_bits.div_ceil(8);
            self.stats.record_compressed_send(
                original_header_bytes,
                schc_header_bytes,
                (compressed.rule_id, compressed.rule_id_length),
            );
            self.trace_packet(
                "compress",
                direction,
                Some((compressed.rule_id, compressed.rule_id_length)),
                packet.len(),
                framed.len(),
            );
        }
        result
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let received = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        let rules = self.current_rules().map_err(io_error)?;
        let direction = self.role.incoming_direction();

        for i in 0..received {
            let wire_len = meta[i].len;
            let frame = bufs[i][..wire_len].to_vec();
            let (compressed, compressed_bits) = decode_schc_frame(&frame).map_err(io_error)?;
            let compressed_len = compressed.len();
            let pre_match_rule = match_rule_id(compressed, &rules)
                .ok()
                .map(|r| (r.rule_id, r.rule_id_length));
            self.trace_match_stage(
                "decompress-pre",
                direction,
                compressed_len,
                &format!("rules={}", rules.len()),
            );
            self.trace_match_result(
                "decompress-match",
                direction,
                pre_match_rule,
                compressed_len,
                Some("stage=pre"),
            );
            let decompressed = match decompress_packet_with_bit_length(
                compressed,
                &rules,
                direction,
                None,
                Some(compressed_bits),
            ) {
                Ok(packet) => {
                    self.trace_match_result(
                        "decompress-match",
                        direction,
                        Some((packet.rule_id, packet.rule_id_length)),
                        compressed_len,
                        Some("result=ok"),
                    );
                    packet
                }
                Err(e) => {
                    self.stats.record_decompress_failure();
                    let context = format!("result=err, reason={e:?}");
                    self.trace_match_result(
                        "decompress-match",
                        direction,
                        pre_match_rule,
                        compressed_len,
                        Some(&context),
                    );
                    self.trace_packet(
                        "decompress-fail",
                        direction,
                        pre_match_rule,
                        compressed_len,
                        0,
                    );
                    return Poll::Ready(Err(io_error(anyhow!(
                        "failed to decompress SCHC datagram: {e:?}"
                    ))));
                }
            };
            let payload = match extract_udp_payload(&decompressed.full_data) {
                Ok(payload) => payload,
                Err(e) => {
                    self.stats.record_decompress_failure();
                    self.trace_packet(
                        "decompress-fail",
                        direction,
                        Some((decompressed.rule_id, decompressed.rule_id_length)),
                        compressed_len,
                        decompressed.full_data.len(),
                    );
                    return Poll::Ready(Err(io_error(e)));
                }
            };

            if payload.len() > bufs[i].len() {
                return Poll::Ready(Err(io::Error::other(format!(
                    "decompressed packet ({}) exceeds recv buffer ({})",
                    payload.len(),
                    bufs[i].len()
                ))));
            }

            bufs[i][..payload.len()].copy_from_slice(payload);
            meta[i].len = payload.len();
            meta[i].stride = payload.len();
            let original_header_bytes = decompressed.header_data.len();
            let compressed_header_bits = compressed_bits.saturating_sub(payload.len() * 8);
            let schc_header_bytes = compressed_header_bits.div_ceil(8);
            self.stats
                .record_decompressed_receive(original_header_bytes, schc_header_bytes);
            self.trace_packet(
                "decompress",
                direction,
                Some((decompressed.rule_id, decompressed.rule_id_length)),
                wire_len,
                decompressed.full_data.len(),
            );
        }

        Poll::Ready(Ok(received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

fn io_error(err: anyhow::Error) -> io::Error {
    io::Error::other(err.to_string())
}

fn encode_coreconf_message(
    message_type: CoreconfMessageType,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if payload.is_empty() {
        bail!("CORECONF message payload is empty");
    }

    let mut message = Vec::with_capacity(CORECONF_MESSAGE_PREFIX_BYTES + payload.len());
    message.extend_from_slice(&CORECONF_MESSAGE_MAGIC);
    message.push(CORECONF_MESSAGE_VERSION);
    message.push(message_type as u8);
    message.extend_from_slice(payload);
    Ok(message)
}

fn decode_coreconf_message(message: &[u8]) -> anyhow::Result<(CoreconfMessageType, &[u8])> {
    if message.len() < CORECONF_MESSAGE_PREFIX_BYTES {
        bail!(
            "invalid CORECONF message: {} bytes (expected at least {} bytes)",
            message.len(),
            CORECONF_MESSAGE_PREFIX_BYTES
        );
    }
    if message[..4] != CORECONF_MESSAGE_MAGIC {
        bail!("invalid CORECONF message magic");
    }

    let version = message[4];
    if version != CORECONF_MESSAGE_VERSION {
        bail!(
            "unsupported CORECONF message version {version} (expected {})",
            CORECONF_MESSAGE_VERSION
        );
    }

    let message_type = CoreconfMessageType::from_u8(message[5]).ok_or_else(|| {
        anyhow!(
            "unsupported CORECONF message type {}",
            message[CORECONF_MESSAGE_PREFIX_BYTES - 1]
        )
    })?;
    Ok((message_type, &message[CORECONF_MESSAGE_PREFIX_BYTES..]))
}

fn encode_schc_frame(bit_length: usize, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let bit_length = u32::try_from(bit_length).context("SCHC bit length exceeds u32")?;
    let mut framed = Vec::with_capacity(SCHC_FRAME_BITLEN_PREFIX_BYTES + data.len());
    framed.extend_from_slice(&bit_length.to_be_bytes());
    framed.extend_from_slice(data);
    Ok(framed)
}

fn decode_schc_frame(frame: &[u8]) -> anyhow::Result<(&[u8], usize)> {
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

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Up => "up",
        Direction::Down => "down",
    }
}

fn extract_udp_payload(packet: &[u8]) -> anyhow::Result<&[u8]> {
    if packet.len() >= 62 && packet[12] == 0x86 && packet[13] == 0xdd {
        let payload_start = 14 + 40 + 8;
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

fn extract_learning_fields(packet: &[u8], state: &mut LearningState) -> Vec<(FieldId, Vec<u8>)> {
    if packet.len() < 14 + 40 + 8 {
        return vec![];
    }

    let ipv6 = &packet[14..];
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
        let udp = &ipv6[40..];
        fields.push((FieldId::UdpSrcPort, udp[0..2].to_vec()));
        fields.push((FieldId::UdpDstPort, udp[2..4].to_vec()));
        fields.push((FieldId::UdpDevPort, udp[0..2].to_vec()));
        fields.push((FieldId::UdpAppPort, udp[2..4].to_vec()));
        fields.push((FieldId::UdpLen, udp[4..6].to_vec()));
        fields.push((FieldId::UdpCksum, udp[6..8].to_vec()));
        fields.extend(extract_quic_learning_fields(&udp[8..], state));
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
    if let (Some(dcid_len), Some(short_dcid)) = (state.short_dcid_len, state.short_dcid.as_ref()) {
        if dcid_len > 0 && payload.len() >= 1 + dcid_len {
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
    }
    fields
}

#[allow(clippy::too_many_arguments)]
fn build_ipv6_udp_packet(
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
    let mut packet = Vec::with_capacity(14 + 40 + 8 + payload.len());

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
