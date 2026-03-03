use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

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
    pub(super) fn record_compressed_send(
        &self,
        original_bytes: usize,
        schc_bytes: usize,
        rule: (u32, u8),
    ) {
        self.compressed_sends.fetch_add(1, Ordering::Relaxed);
        self.original_send_bytes
            .fetch_add(original_bytes as u64, Ordering::Relaxed);
        self.schc_send_bytes
            .fetch_add(schc_bytes as u64, Ordering::Relaxed);
        let mut by_rule = self.compressed_by_rule.write();
        *by_rule.entry(rule).or_insert(0) += 1;
    }

    pub(super) fn record_decompressed_receive(&self, original_bytes: usize, schc_bytes: usize) {
        self.decompressed_receives.fetch_add(1, Ordering::Relaxed);
        self.original_receive_bytes
            .fetch_add(original_bytes as u64, Ordering::Relaxed);
        self.schc_receive_bytes
            .fetch_add(schc_bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn record_compress_failure(&self) {
        self.compress_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_decompress_failure(&self) {
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
        return 0.0;
    }
    let saved = original as f64 - schc as f64;
    (saved * 100.0) / original as f64
}
