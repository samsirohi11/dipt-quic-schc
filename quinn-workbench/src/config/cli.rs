use clap::{Parser, Subcommand, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
pub struct CliOpt {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Run the QUIC simulation
    Quic(QuicOpt),
    /// Run a ping simulation at the UDP level
    Ping(PingOpt),
    /// Run a throughput simulation at the UDP level
    Throughput(ThroughputOpt),
    /// Return the identifier of the async runtime used
    Rt,
}

#[derive(Parser, Debug, Clone)]
pub struct NetworkOpt {
    /// The IP address of the node used as a client
    #[arg(long)]
    pub client_ip_address: IpAddr,

    /// The IP address of the node used as a server
    #[arg(long)]
    pub server_ip_address: IpAddr,

    /// Whether the run should be non-deterministic, i.e. using a non-constant seed for the random
    /// number generators
    #[arg(long)]
    pub non_deterministic: bool,

    /// Quinn's random seed, which you can control to generate deterministic results (Quinn uses
    /// randomness internally)
    #[arg(long, default_value_t = 0)]
    pub quinn_rng_seed: u64,

    /// The random seed used for the simulated network (governing packet loss, duplication and
    /// reordering)
    #[arg(long, default_value_t = 42)]
    pub network_rng_seed: u64,

    /// Path to the JSON file containing the network graph
    #[arg(long)]
    pub network_graph: PathBuf,

    /// Path to the JSON file containing the network events
    #[arg(long)]
    pub network_events: PathBuf,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchcLearnerProfile {
    Fast,
    Balanced,
    Strict,
}

#[derive(Parser, Debug, Clone)]
pub struct QuicOpt {
    /// The number of requests that should be made
    #[arg(long, default_value_t = 10)]
    pub requests: u32,

    /// The number of concurrent connections used when making the requests
    #[arg(long, default_value_t = 1)]
    pub concurrent_connections: u8,

    /// The number of concurrent streams per connection used when making the requests
    #[arg(long, default_value_t = 1)]
    pub concurrent_streams_per_connection: u32,

    /// The size of each response, in bytes
    #[arg(long, default_value_t = 1024)]
    pub response_size: usize,

    /// Route QUIC UDP datagrams through SCHC compression/decompression
    #[arg(
        long,
        default_value_t = false,
        requires_all = ["schc_m_rules", "schc_app_rules", "schc_sid_file"]
    )]
    pub schc_enabled: bool,

    /// Path to SCHC M-Rules SOR file used by manager state
    #[arg(long)]
    pub schc_m_rules: Option<PathBuf>,

    /// Path to SCHC application rules SOR file for QUIC payload compression
    #[arg(long)]
    pub schc_app_rules: Option<PathBuf>,

    /// Path to SCHC SID file used to parse SOR rules
    #[arg(long)]
    pub schc_sid_file: Option<PathBuf>,

    /// Print per-packet SCHC transport tracing details
    #[arg(long, default_value_t = false, requires = "schc_enabled")]
    pub schc_verbose: bool,

    /// Estimated RTT used by SCHC manager guard period logic
    #[arg(long, default_value_t = 100)]
    pub schc_estimated_rtt_ms: u64,

    /// Enable staged SCHC learning with a preset profile
    #[arg(long, value_enum, requires = "schc_enabled")]
    pub schc_learner_profile: Option<SchcLearnerProfile>,

    #[command(flatten)]
    pub network: NetworkOpt,
}

#[derive(Parser, Debug, Clone)]
pub struct PingOpt {
    /// The duration of the run, after which we will stop sending pings and the program will
    /// terminate
    #[arg(long)]
    pub duration_ms: u64,

    /// The interval at which ping packets will be sent
    #[arg(long)]
    pub interval_ms: u64,

    /// The deadline between sending a ping and receiving a reply (after which the ping itself or
    /// its reply are considered lost)
    #[arg(long, default_value_t = 10_000)]
    pub deadline_ms: u64,

    #[command(flatten)]
    pub network: NetworkOpt,
}

#[derive(Parser, Debug, Clone)]
pub struct ThroughputOpt {
    /// The duration of the run
    #[arg(long)]
    pub duration_ms: u64,

    /// The bitrate at which information should be sent
    ///
    /// If not provided, we find the link with the highest capacity and use its doubled bandwidth
    #[arg(long)]
    pub send_bps: Option<u64>,

    #[command(flatten)]
    pub network: NetworkOpt,
}
