use crate::quic::schc_transport::learning::LearningSync;
use crate::quic::schc_transport::learning_rules::rule_has_quic_fields;
use crate::quic::schc_transport::packet::{
    build_ipv6_udp_packet, decode_schc_frame, direction_name, encode_schc_frame,
    extract_udp_payload,
};
use crate::quic::schc_transport::stats::SchcTransportStats;
use crate::quic::schc_transport::types::{FLOW_LABEL, NodeRole, SharedManager, TRAFFIC_CLASS};
use anyhow::Context as _;
use anyhow::anyhow;
use in_memory_network::quinn_interop::InMemoryUdpSocket;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use schc::{
    Direction, Rule, build_tree, compress_packet, decompress_packet_with_bit_length, match_rule_id,
};
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

#[derive(Debug)]
struct AlwaysWritablePoller;

impl UdpPoller for AlwaysWritablePoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(super) struct SchcUdpSocket {
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
    pub(super) fn new(
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

    fn local_node(&self) -> String {
        self.local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string())
    }

    fn format_rule(rule: Option<(u32, u8)>) -> String {
        rule.map(|(id, len)| format!("{id}/{len}"))
            .unwrap_or_else(|| "no-match".to_string())
    }

    fn trace_match_stage(
        &self,
        action: &str,
        direction: Direction,
        packet_bytes: usize,
        context: &str,
    ) {
        let node = self.local_node();
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
        let node = self.local_node();
        let rule = Self::format_rule(rule);
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
        let node = self.local_node();
        let rule = Self::format_rule(rule);
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
