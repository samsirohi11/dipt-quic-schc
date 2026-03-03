use crate::config::cli::QuicOpt;
use anyhow::{Context as _, bail};
use in_memory_network::quinn_interop::InMemoryUdpSocket;
use parking_lot::RwLock;
use quinn::AsyncUdpSocket;
use rust_coreconf::SidFile;
use schc_coreconf::{MRuleSet, SchcCoreconfManager, load_sor_rules};
use std::sync::Arc;
use std::time::Duration;

mod coreconf;
mod learning;
mod learning_extract;
mod learning_rules;
mod packet;
mod socket;
mod stats;
mod types;

use self::learning::LearningSync;
use self::socket::SchcUdpSocket;
use self::types::{LearnerProfilePolicy, NodeRole, profile_policy};

#[allow(unused_imports)]
pub use self::stats::{SchcTransportStats, SchcTransportStatsSnapshot, print_summary};

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

    let learner_policy = quic_opt.schc_learner_profile.map(profile_policy);
    let learning = learner_policy.map(|policy| {
        Arc::new(LearningSync::new(
            policy,
            client_manager.clone(),
            server_manager.clone(),
        ))
    });

    print_startup_summary(quic_opt, learner_policy);

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

fn print_startup_summary(quic_opt: &QuicOpt, learner_policy: Option<LearnerProfilePolicy>) {
    println!("--- SCHC over QUIC transport ---");
    println!("* Enabled QUIC SCHC mode");
    if quic_opt.schc_verbose {
        println!("* Verbose packet tracing enabled");
    }
    if let Some(policy) = learner_policy {
        println!(
            "* Rule learning sync enabled with {} profile",
            policy.name
        );
    }
}

fn path_option<'a>(
    value: &'a Option<std::path::PathBuf>,
    arg: &str,
) -> anyhow::Result<&'a str> {
    let Some(path) = value else {
        bail!("missing required option {arg} when SCHC mode is enabled");
    };
    path.to_str()
        .with_context(|| format!("option {arg} has non-utf8 path: {}", path.display()))
}
