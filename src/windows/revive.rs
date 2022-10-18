use crate::utils::{
    config::SysConfig,
    tools::{exec_cmd, verify_config, yes_no},
    user::{ADUserInfo, LocalUserInfo},
};
use log::{debug, error, info, warn};
use std::fs;
use std::fs::File;
use std::io::BufReader;

fn configure_firewall(config: &SysConfig) {
    debug!("Resetting Firewall and deleting old rules");
    if !exec_cmd("netsh", &["advfirewall", "reset"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to reset firewall!");
    };
    if !exec_cmd(
        "netsh",
        &["advfirewall", "set", "allprofiles", "state", "on"],
        false,
    )
    .unwrap()
    .wait()
    .unwrap()
    .success()
    {
        error!("Failed to turn on firewalls!");
    };
    if !exec_cmd(
        "netsh",
        &["advfirewall", "firewall", "delete", "rule", "name=all"],
        false,
    )
    .unwrap()
    .wait()
    .unwrap()
    .success()
    {
        error!("Failed to delete old firewall rules!");
    };
    info!("Firewall has been wiped");
    debug!("Adding New Rules");
    if !exec_cmd(
        "netsh",
        &[
            "advfirewall",
            "set",
            "firewallpolicy",
            "blockinbound,blockoutbound",
        ],
        false,
    )
    .unwrap()
    .wait()
    .unwrap()
    .success()
    {
        error!("Failed to block firewall in/out!");
    };
    if !exec_cmd(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=\"ICMP\"",
            "action=allow",
            "protocol=icmpv4:8,any",
        ],
        false,
    )
    .unwrap()
    .wait()
    .unwrap()
    .success()
    {
        error!("Failed to allow ICMP!");
    };
    info!("Added ICMP Rule");
    for port in &config.ports {
        if !exec_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", port),
                "action=allow",
                "protocol=tcp",
                &format!("remoteport={}", port),
                "dir=in",
            ],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to add allow in tcp port {}!", port);
        };
        if !exec_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", port),
                "action=allow",
                "protocol=tcp",
                &format!("localport={}", port),
                "dir=out",
            ],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to add allow out tcp port {}!", port);
        };
        if !exec_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", port),
                "action=allow",
                "protocol=udp",
                &format!("remoteport={}", port),
                "dir=in",
            ],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to add allow in udp port {}!", port);
        };
        if !exec_cmd(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", port),
                "action=allow",
                "protocol=udp",
                &format!("localport={}", port),
                "dir=out",
            ],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to add allow out udp port {}!", port);
        };
        info!("Add Port {} Rule", port);
    }
}

fn audit_local_users(config: &SysConfig) {
    for user in LocalUserInfo::get_all_users() {
        println!("{:?}", user);
        if user.groups.contains(&"Domain Admins".to_owned()) {
            warn!("{} is a Domain Admin!", user.name);
        }
        if user.groups.contains(&"Schema Admins".to_owned()) {
            warn!("{} is a Schema Admin!", user.name);
        }
        if user.groups.contains(&"Enterprise Admins".to_owned()) {
            warn!("{} is an Enterprise Admin!", user.name);
        }
        if user.groups.contains(&"Administrators".to_owned()) {
            warn!("{} is an administrator!", user.name);
        }
        if user.enabled && !config.users.contains(&user.name) {
            warn!("AD User {} was found active and disabled", user.name);
            user.shutdown();
        }
        //user.change_password(&password);
    }
}

fn audit_ad_users(config: &SysConfig) {
    for user in ADUserInfo::get_all_users() {
        println!("{:?}", user);
        if user.groups.contains(&"Domain Admins".to_owned()) {
            warn!("{} is a Domain Admin!", user.name);
        }
        if user.groups.contains(&"Schema Admins".to_owned()) {
            warn!("{} is a Schema Admin!", user.name);
        }
        if user.groups.contains(&"Enterprise Admins".to_owned()) {
            warn!("{} is an Enterprise Admin!", user.name);
        }
        if user.groups.contains(&"Administrators".to_owned()) {
            warn!("{} is an administrator!", user.name);
        }
        if user.enabled && !config.users.contains(&user.name) {
            warn!("AD User {} was found active and disabled", user.name);
            user.shutdown();
        }
        // user.change_password(&password);
    }
}

fn select_services(config: &SysConfig) {
    for service in &config.services {
        if !exec_cmd(
            "powershell",
            &[
                "-ExecutionPolicy",
                "Bypass",
                &format!("Start-Service -Name {}", service),
            ],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to start service {}", service);
            continue;
        };
        info!("Service {} will be maintained and kept alive", service);
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("./config.json")?;
    let reader = BufReader::new(file);
    let config: SysConfig = serde_json::from_reader(reader)?;
    if !verify_config(&config) {
        panic!("Corrupted config.json, re-run setup");
    }
    configure_firewall(&config);
    //let password = prompt_password("Enter password for valid users: ").unwrap();
    audit_local_users(&config);
    if yes_no("Check AD Users (Must be on AD Server)".to_owned()) {
        audit_ad_users(&config);
    }
    select_services(&config);
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    info!("Data on system has been added to config.json");
    Ok(())
}
