use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize)]
pub struct SysConfig {
    pub ip: IpAddr,
    pub interface: String,
    pub ports: Vec<String>,
    pub services: Vec<String>,
    pub users: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Permissions {
    pub ip: String,
    pub ports: Vec<String>,
    pub allow_icmp: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PfConfig {
    pub lan_ip: IpAddr,
    pub lan_subnet: String,
    pub lan_interface: String,
    pub wan_ip: IpAddr,
    pub wan_subnet: String,
    pub wan_interface: String,
    pub dmz_ip: Option<IpAddr>,
    pub dmz_subnet: Option<String>,
    pub dmz_interface: Option<String>,
    pub version: Option<String>,
    pub permissions: Vec<Permissions>,
    pub users: Vec<String>,
}
