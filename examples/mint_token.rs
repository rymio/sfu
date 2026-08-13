//! Mint a join token for manually testing the `chat` example's `register` step, until a
//! real client (the mobile app, or a browser test page with a token field) mints its own.
//!
//! ```bash
//! cargo run --example mint_token -- --secret "$SFU_JOIN_SECRET" \
//!     --room 3fa85f64-5717-4562-b3fc-2c963f66afa6 --client 1
//! ```
//!
//! Prints the token to stdout. `examples/chat.html` has no token input field today — this
//! is for driving the WS `register` protocol directly (a test script, or a browser
//! devtools console) rather than through the bundled page.

// Shares `chat`'s security module but only exercises `mint_join_token` — the rest
// (`verify_join_token`, TURN credential issuance, `SignalingSecurity`) is legitimately
// unused from this binary's perspective.
#[path = "signaling/security.rs"]
#[allow(dead_code)]
mod security;

use clap::Parser;
use sfu::{ClientId, RoomId};

#[derive(Parser)]
#[command(about = "Mint a join token for the sfu chat example's register step")]
struct Cli {
    /// Must match the `chat` server's `--join-secret` / `SFU_JOIN_SECRET`.
    #[arg(long, env = "SFU_JOIN_SECRET")]
    secret: String,
    #[arg(long)]
    room: RoomId,
    #[arg(long)]
    client: ClientId,
    #[arg(long, default_value_t = 3600)]
    ttl: u64,
}

fn main() {
    let cli = Cli::parse();
    let token = security::mint_join_token(&cli.secret, cli.room, cli.client, cli.ttl);
    println!("{token}");
}
