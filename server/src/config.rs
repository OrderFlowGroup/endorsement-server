use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /** Endorsement key file path */
    pub endorsement_key_path: Option<String>,

    /** Each endorsement expires this many seconds after it is issued */
    pub expiration_in_seconds: Option<u8>,

    /** If true, then payment in lieu approval endpoint will be disabled */
    pub disable_payment_in_lieu_approval: Option<bool>,

    /** Optional server settings */
    pub server: Option<ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /** Server port */
    pub port: u16,

    /** CORS settings */
    pub cors: Option<ServerCorsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCorsConfig {
    pub origin: String,
}

impl Config {
    /// Read a YAML config file
    pub fn read_yaml(filepath: &str) -> Result<Config, String> {
        let yaml_str = fs::read_to_string(filepath)
            .map_err(|e| format!("Failed to read config file {filepath}: {e}"))?;
        serde_yaml::from_str::<Config>(&yaml_str)
            .map_err(|e| format!("Failed to parse config file {filepath}: {e}"))
    }
}
