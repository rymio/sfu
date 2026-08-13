use clap::Parser;
use env_logger::Target;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::io::BufReader;
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{self};
use std::{fs::OpenOptions, io::Write, str::FromStr};
use wg::WaitGroup;

mod signaling;
mod util;

use signaling::*;

#[derive(Default, Debug, Copy, Clone, clap::ValueEnum)]
enum Level {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl From<Level> for log::LevelFilter {
    fn from(level: Level) -> Self {
        match level {
            Level::Error => log::LevelFilter::Error,
            Level::Warn => log::LevelFilter::Warn,
            Level::Info => log::LevelFilter::Info,
            Level::Debug => log::LevelFilter::Debug,
            Level::Trace => log::LevelFilter::Trace,
        }
    }
}

#[derive(Parser)]
#[command(name = "SFU Server")]
#[command(author = "Rusty Rain <y@ngr.tc>")]
#[command(version = "0.1.0")]
#[command(about = "An example of SFU Server", long_about = None)]
struct Cli {
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(short, long, default_value_t = 8080)]
    signal_port: u16,
    #[arg(long, default_value_t = 3478)]
    media_port_min: u16,
    #[arg(long, default_value_t = 3495)]
    media_port_max: u16,

    #[arg(short, long)]
    force_local_loop: bool,
    #[arg(short, long)]
    debug: bool,
    #[arg(long)]
    tls: bool,
    #[arg(short, long, default_value_t = Level::Info)]
    #[clap(value_enum)]
    level: Level,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    #[arg(long, default_value_t = format!(""))]
    web_root: String,

    /// Shared secret `register` join tokens must be signed with (mint one with the
    /// `mint_token` example) — see `security::verify_join_token`. Optional: with no secret
    /// configured, `register` accepts any room/client with no token check at all, matching
    /// this crate's original behavior (and what `tests/` relies on) — see this file's
    /// startup warning for why that's a real tradeoff, not a free default.
    #[arg(long, env = "SFU_JOIN_SECRET")]
    join_secret: Option<String>,
    /// Shared secret matching a TURN server's `static-auth-secret` (e.g. `turn1.sigs.au`'s
    /// coturn config) — used only to *issue* credentials to clients over signaling; the
    /// SFU's own ICE-lite connectivity never uses TURN itself. Optional: with none
    /// configured, no TURN credentials are issued to clients at all.
    #[arg(long, env = "SFU_TURN_SECRET")]
    turn_secret: Option<String>,
    /// Comma-separated TURN/STUN URIs handed to clients alongside issued credentials.
    #[arg(
        long,
        env = "SFU_TURN_URIS",
        default_value = "turn:turn1.sigs.au:3478,turns:turn1.sigs.au:443?transport=tcp,stun:turn1.sigs.au:3478"
    )]
    turn_uris: String,
    /// TURN credential TTL in seconds.
    #[arg(long, default_value_t = 3600)]
    turn_credential_ttl: u64,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.join_secret.is_none() {
        eprintln!(
            "WARNING: --join-secret / SFU_JOIN_SECRET not set — register is UNAUTHENTICATED, \
             anyone who reaches this port can join any room. Fine for local/CI testing, \
             do not run a public deployment like this."
        );
    }
    if cli.turn_secret.is_none() {
        eprintln!(
            "WARNING: --turn-secret / SFU_TURN_SECRET not set — no TURN credentials will be \
             issued; clients that can't reach this host directly (restrictive NAT/firewall) \
             won't be able to connect."
        );
    }
    if cli.debug {
        env_logger::Builder::new()
            .target(if !cli.output_log_file.is_empty() {
                Target::Pipe(Box::new(
                    OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(cli.output_log_file)?,
                ))
            } else {
                Target::Stdout
            })
            .format(|buf, record| {
                writeln!(
                    buf,
                    "{}:{} [{}] {} - {}",
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.level(),
                    chrono::Local::now().format("%H:%M:%S.%6f"),
                    record.args()
                )
            })
            .filter(None, cli.level.into())
            .init();
    }

    let (certificate, private_key) = if cli.tls {
        let cert = std::fs::read("/cert/cert.pem")
            .map_err(|e| anyhow::anyhow!("Failed to read /cert/cert.pem: {}", e))?;
        let key = std::fs::read("/cert/key.pem")
            .map_err(|e| anyhow::anyhow!("Failed to read /cert/key.pem: {}", e))?;
        (cert, key)
    } else {
        (
            include_bytes!("util/cer.pem").to_vec(),
            include_bytes!("util/key.pem").to_vec(),
        )
    };

    // Figure out some public IP address, since Firefox will not accept 127.0.0.1 for WebRTC traffic.
    let host_addr = if cli.host == "127.0.0.1" && !cli.force_local_loop {
        util::select_host_address()
    } else {
        IpAddr::from_str(&cli.host)?
    };

    let media_ports: Vec<u16> = (cli.media_port_min..=cli.media_port_max).collect();
    let (stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(1);
    let mut media_port_thread_map = HashMap::new();

    let wait_group = WaitGroup::new();

    for port in media_ports {
        let worker = wait_group.add(1);
        let stop_rx = stop_rx.clone();
        let (signaling_tx, signaling_rx) = mpsc::sync_channel(1);

        // Spin up a UDP socket for the RTC. All WebRTC traffic is going to be multiplexed over this single
        // server socket. Clients are identified via their respective remote (UDP) socket address.
        let socket = UdpSocket::bind(format!("{host_addr}:{port}"))
            .unwrap_or_else(|_| panic!("binding to {host_addr}:{port}"));

        media_port_thread_map.insert(port, signaling_tx);

        // The run loop is on a separate thread to the web server.
        std::thread::spawn(move || {
            if let Err(err) = run(stop_rx, socket, signaling_rx) {
                eprintln!("run_sfu got error: {}", err);
            }
            worker.done();
        });
    }

    let media_port_thread_map = Arc::new(media_port_thread_map);
    let signal_port = cli.signal_port;

    // TLS-only signaling: serve the page over HTTPS and upgrade `/ws` to a WebSocket.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto provider");
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(&certificate[..]))
            .collect::<Result<_, _>>()
            .expect("parse TLS certificate chain");
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(&private_key[..]))
            .expect("read TLS private key")
            .expect("no private key found in key.pem");
    let tls_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("build rustls server config"),
    );

    let listener = TcpListener::bind(format!("{}:{}", host_addr, signal_port))
        .unwrap_or_else(|e| panic!("binding signaling port {signal_port}: {e}"));
    println!("Connect a browser to https://{}:{}", host_addr, signal_port);

    let security = Arc::new(signaling::security::SignalingSecurity {
        join_secret: cli.join_secret,
        turn_secret: cli.turn_secret,
        turn_uris: cli
            .turn_uris
            .split(',')
            .map(str::to_owned)
            .filter(|s| !s.is_empty())
            .collect(),
        turn_credential_ttl: cli.turn_credential_ttl,
    });

    let signal_handle = {
        let stop_rx = stop_rx.clone();
        let media_port_thread_map = media_port_thread_map.clone();
        let web_root = if cli.web_root.is_empty() {
            None
        } else {
            Some(cli.web_root)
        };
        let web_root = Arc::new(web_root);
        std::thread::spawn(move || {
            signaling::serve(
                stop_rx,
                listener,
                tls_config,
                media_port_thread_map,
                web_root,
                security,
            );
        })
    };

    println!("Press Ctrl-C to stop");
    std::thread::spawn(move || {
        let mut stop_tx = Some(stop_tx);
        ctrlc::set_handler(move || {
            if let Some(stop_tx) = stop_tx.take() {
                let _ = stop_tx.send(());
            }
        })
        .expect("Error setting Ctrl-C handler");
    });
    let _ = stop_rx.recv();
    println!("Wait for Signaling Sever and Media Server Gracefully Shutdown...");
    wait_group.wait();
    println!("signaling server is gracefully down");
    let _ = signal_handle.join();

    Ok(())
}
