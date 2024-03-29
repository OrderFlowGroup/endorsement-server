use clap::{Args, Parser, Subcommand};
use config::{Config, ServerConfig, ServerCorsConfig};
use server::{run_server, ServerContext};
use signatory_client_lib::endorsement_key::EndorsementKey;
use std::{
    env, fs::OpenOptions, io::Write, os::unix::prelude::OpenOptionsExt, path::Path, process,
};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::oneshot,
};
use tracing_subscriber::prelude::*;

mod config;
mod server;
mod trace;

const DEFAULT_PORT: u16 = 8082;
const EXPIRATION_IN_SECONDS_MIN: u8 = 5;
const EXPIRATION_IN_SECONDS_MAX: u8 = 120;
const DEFAULT_EXPIRATION_IN_SECONDS: u8 = EXPIRATION_IN_SECONDS_MAX;

const DEFAULT_KEYGEN_PATH: &str = "./endorsementKey.json";

#[tokio::main]
async fn main() {
    let top_command = Cli::parse();
    match top_command.command {
        Commands::Start(args) => {
            const RUST_LOG_ENV_VAR: &str = "RUST_LOG";
            if env::var(RUST_LOG_ENV_VAR).is_err() {
                // Use info log level by default
                env::set_var(RUST_LOG_ENV_VAR, "info");
            }
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::from_env(RUST_LOG_ENV_VAR))
                .with(tracing_subscriber::fmt::Layer::default().with_ansi(false))
                .init();

            let (server_exit_send, server_exit_recv) = oneshot::channel();
            let (sigint_send, sigint_recv) = oneshot::channel();
            tokio::spawn(async move {
                start(args).await;
                server_exit_send.send(())
            });

            let mut sigint_stream = signal(SignalKind::interrupt()).unwrap_or_else(|e| {
                tracing::error!("Failed to set up signal handler: {e}");
                process::exit(1);
            });
            tokio::spawn(async move {
                sigint_stream.recv().await;
                sigint_send.send(())
            });

            tokio::select! {
                _ = server_exit_recv => {
                    tracing::error!("Failed to start server. Exiting...");
                }
                _ = sigint_recv => {
                    tracing::info!("Received SIGINT. Exiting...");
                }
            }
        }

        Commands::KeyCommand(args) => match args.key_commands {
            KeySubCommands::Generate(args) => {
                key_generate(args);
            }

            KeySubCommands::Parse(args) => {
                key_parse(args);
            }
        },
    }
}

async fn start(args: StartArgs) {
    let config = args.config_path.map(|config_path| {
        Config::read_yaml(&config_path).unwrap_or_else(|e| {
            tracing::error!(e);
            process::exit(1);
        })
    });

    let endorsement_key = args
        .endorsement_key_path
        .or_else(|| config.clone().and_then(|x| x.endorsement_key_path))
        .map(|path| EndorsementKey::from_file(&path))
        .or_else(|| {
            env::var("ENDORSEMENT_KEY").map_or(None, |raw| Some(EndorsementKey::from_raw_str(&raw)))
        })
        .unwrap_or_else(|| {
            tracing::error!(
                "Endorsement key not provided via CLI, config file, or ENDORSEMENT_KEY environment \
                variable. You must specify an endorsement key using one of these methods."
            );
            process::exit(1);
        })
        .unwrap_or_else(|e| {
            tracing::error!(e);
            process::exit(1);
        });

    let expiration_in_seconds = args
        .expiration_in_seconds
        .or_else(|| config.clone().and_then(|x| x.expiration_in_seconds))
        .unwrap_or(DEFAULT_EXPIRATION_IN_SECONDS);
    if expiration_in_seconds < EXPIRATION_IN_SECONDS_MIN {
        tracing::error!(
            "Endorsement expiration must be at least {EXPIRATION_IN_SECONDS_MIN} seconds"
        );
        process::exit(1);
    } else if expiration_in_seconds > EXPIRATION_IN_SECONDS_MAX {
        tracing::error!(
            "Endorsement expiration must be at most {EXPIRATION_IN_SECONDS_MAX} seconds"
        );
        process::exit(1);
    }

    let disable_payment_in_lieu_approval = args
        .disable_payment_in_lieu_approval
        .or_else(|| {
            config
                .clone()
                .and_then(|x| x.disable_payment_in_lieu_approval)
        })
        .unwrap_or(false);

    let port = args
        .server_port
        .or_else(|| config.clone().and_then(|c| c.server.map(|s| s.port)))
        .unwrap_or(DEFAULT_PORT);

    let cors_origin = args.server_cors_origin.or_else(|| {
        config
            .clone()
            .and_then(|c| c.server.and_then(|s| s.cors.map(|sc| sc.origin)))
    });

    let server_context = ServerContext {
        endorsement_key,
        expiration_in_seconds,
        disable_payment_in_lieu_approval,
        server: ServerConfig {
            port,
            cors: cors_origin.map(|origin| ServerCorsConfig { origin }),
        },
    };

    run_server(server_context).await;
}

fn key_generate(args: KeyGenerateArgs) {
    let outfile = &args.outfile;
    if Path::new(&outfile).exists() && !args.force {
        print_and_exit(format!("Refusing to overwrite {outfile} without --force"));
    }
    let endorsement_key = EndorsementKey::generate();
    let base58_public_key = &endorsement_key.base58_public_key;
    println!("Generated endorsement key: {base58_public_key}");
    let serialized = endorsement_key.serialize().unwrap_or_else(|e| {
        print_and_exit(e);
    });
    println!("Writing endorsement key to {outfile}");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(outfile)
        .unwrap_or_else(|e| {
            print_and_exit(format!("Failed to open outfile {outfile}: {e}"));
        });
    file.write_all(serialized.as_bytes()).unwrap_or_else(|e| {
        print_and_exit(format!("Failed to write secret key to {outfile}: {e}"));
    });
}

fn key_parse(args: KeyParseArgs) {
    let parsed = EndorsementKey::from_file(&args.filepath).unwrap_or_else(|e| {
        print_and_exit(e);
    });
    println!("{}", parsed.base58_public_key);
}

fn print_and_exit(error_msg: String) -> ! {
    println!("{error_msg}");
    process::exit(1);
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the endorsement server
    Start(StartArgs),

    /// Endorsement key commands
    #[clap(name = "key")]
    KeyCommand(KeyCommand),
}

#[derive(Args)]
struct StartArgs {
    /// Config filepath
    #[arg(short, long = "config", name = "CONFIG_FILEPATH")]
    config_path: Option<String>,

    /// Endorsement key filepath
    #[arg(long, name = "ENDORSEMENT_KEY_FILEPATH")]
    endorsement_key_path: Option<String>,

    /// Each endorsement expires this many seconds after it is issued
    #[arg(long, name = "EXPIRATION_IN_SECONDS")]
    expiration_in_seconds: Option<u8>,

    /// Disable payment in lieu approval endpoint
    #[arg(long)]
    disable_payment_in_lieu_approval: Option<bool>,

    /// Port to listen on
    #[arg(long = "server.port", name = "PORT")]
    server_port: Option<u16>,

    /// CORS allowed origin
    #[arg(long = "server.cors.origin", name = "ORIGIN")]
    server_cors_origin: Option<String>,
}

#[derive(Parser)]
struct KeyCommand {
    #[structopt(subcommand)]
    key_commands: KeySubCommands,
}

#[derive(Subcommand)]
enum KeySubCommands {
    /// Generate an endorsement key
    Generate(KeyGenerateArgs),

    /// Show an endorsement key's Base58-encoded public key
    Parse(KeyParseArgs),
}

#[derive(Args)]
struct KeyGenerateArgs {
    /// Filepath for the generated endorsement key
    #[arg(short, long, name = "FILEPATH", default_value_t = String::from(DEFAULT_KEYGEN_PATH))]
    outfile: String,

    /// Overwrite the output file if it already exists
    #[arg(short, long)]
    force: bool,
}

#[derive(Args)]
struct KeyParseArgs {
    /// Filepath for the endorsement key
    #[arg(index = 1, name = "FILEPATH", default_value_t = String::from(DEFAULT_KEYGEN_PATH))]
    filepath: String,
}
