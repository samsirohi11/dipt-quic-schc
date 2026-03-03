use crate::quic::schc_transport::types::{
    CORECONF_MESSAGE_MAGIC, CORECONF_MESSAGE_PREFIX_BYTES, CORECONF_MESSAGE_VERSION,
};
use anyhow::{anyhow, bail};
use base64::Engine;
use schc::rule::{ParsedTargetValue, Rule, RuleValue};
use schc_coreconf::rpc_builder::{EntryModification, parse_duplicate_rule_rpc};
use schc_coreconf::{SchcCoreconfManager, cda_to_sid, mo_to_sid};

#[derive(Clone, Copy, Debug)]
pub(super) enum CoreconfMessageType {
    SchcDeviceDuplicateRule = 1,
}

impl CoreconfMessageType {
    fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::SchcDeviceDuplicateRule),
            _ => None,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::SchcDeviceDuplicateRule => "schc_device->schc_core.duplicate-rule",
        }
    }
}

pub(super) fn build_duplicate_rule_modifications(
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

pub(super) fn apply_duplicate_rule_rpc_payload(
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

pub(super) fn encode_coreconf_message(
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

pub(super) fn format_target_bytes_for_display(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0x".to_string();
    }
    let mut output = String::from("0x");
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

pub(super) fn field_target_value_bytes(field: &schc::rule::Field) -> Option<Vec<u8>> {
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
            insert_optional_u32(&mut entry, "matching-operator-sid", m.matching_operator);
            insert_optional_u32(&mut entry, "comp-decomp-action-sid", m.comp_decomp_action);
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

fn insert_optional_u32(
    entry: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<i64>,
) {
    if let Some(value) = value {
        entry.insert(
            key.to_string(),
            serde_json::Value::Number(value.into()),
        );
    }
}
