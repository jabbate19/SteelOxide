use crate::os::setup;
use crate::utils::{
    config::SysConfig,
    tools::{exec_cmd, verify_config, yes_no},
    user::{ADUserInfo, LocalUserInfo},
};
use clap::ArgMatches;
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::BufReader;

fn configure_firewall(config: &SysConfig) {
    debug!("Resetting Firewall and deleting old rules");
    let reset = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "reset"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    if !reset.status.success() {
        error!(
            "Failed to reset firewall: {}",
            String::from_utf8_lossy(&reset.stderr)
        );
    };
    let on = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "set", "allprofiles", "state", "on"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    if !on.status.success() {
        error!(
            "Failed to turn on firewalls: {}",
            String::from_utf8_lossy(&on.stderr)
        );
    };
    let clear = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "firewall", "delete", "rule", "name=all"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    if !clear.status.success() {
        error!(
            "Failed to delete old firewall rules: {}",
            String::from_utf8_lossy(&clear.stderr)
        );
    };
    info!("Firewall has been wiped");
    debug!("Adding New Rules");
    let block_all = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &[
            "advfirewall",
            "set",
            "currentprofile",
            "firewallpolicy",
            "blockinbound,blockoutbound",
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    if !block_all.status.success() {
        error!(
            "Failed to block firewall in/out: {}",
            String::from_utf8_lossy(&block_all.stderr)
        );
    };
    let add_icmp_in = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=\"ICMP\"",
            "action=allow",
            "protocol=icmpv4:8,any",
            "dir=in",
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();

    if add_icmp_in.status.success() {
        info!("Added ICMP In Rule");
    } else {
        error!(
            "Failed to allow ICMP in: {}",
            String::from_utf8_lossy(&add_icmp_in.stderr)
        );
    };

    let add_icmp_out = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=\"ICMP\"",
            "action=allow",
            "protocol=icmpv4:0,any",
            "dir=out",
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    if add_icmp_out.status.success() {
        info!("Added ICMP Out Rule");
    } else {
        error!(
            "Failed to allow ICMP Out: {}",
            String::from_utf8_lossy(&add_icmp_out.stderr)
        );
    };

    for port in &config.ports {
        let tcp_in = exec_cmd(
            "C:\\Windows\\System32\\netsh.exe",
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
        .wait_with_output()
        .unwrap();
        if !tcp_in.status.success() {
            error!(
                "Failed to add allow in tcp port {}: {}",
                port,
                String::from_utf8_lossy(&tcp_in.stderr)
            );
        };
        let tcp_out = exec_cmd(
            "C:\\Windows\\System32\\netsh.exe",
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
        .wait_with_output()
        .unwrap();
        if !tcp_out.status.success() {
            error!(
                "Failed to add allow out tcp port {}: {}",
                port,
                String::from_utf8_lossy(&tcp_out.stderr)
            );
        };
        let udp_in = exec_cmd(
            "C:\\Windows\\System32\\netsh.exe",
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
        .wait_with_output()
        .unwrap();
        if !udp_in.status.success() {
            error!(
                "Failed to add allow in udp port {}: {}",
                port,
                String::from_utf8_lossy(&udp_in.stderr)
            );
        };
        let udp_out = exec_cmd(
            "C:\\Windows\\System32\\netsh.exe",
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
        .wait_with_output()
        .unwrap();
        if !udp_out.status.success() {
            error!(
                "Failed to add allow out udp port {}: {}",
                port,
                String::from_utf8_lossy(&udp_out.stderr)
            );
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
        // user.change_password(&password);
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
            user.shutdown();
            warn!("AD User {} was found active and disabled", user.name);
        }
        // user.change_password(&password);
    }
}

fn select_services(config: &SysConfig) {
    for service in &config.services {
        let service_status_cmd = exec_cmd(
            "powershell",
            &[
                "-ExecutionPolicy",
                "Bypass",
                &format!("(Get-Service -Name {}).status", service),
            ],
            false,
        )
        .unwrap()
        .wait_with_output()
        .unwrap();
        let service_status_stdout = match service_status_cmd.status.success() {
            true => service_status_cmd.stdout,
            false => {
                error!("Failed to get service {} status", service);
                continue;
            }
        };
        let service_status = String::from_utf8_lossy(&service_status_stdout);
        if service_status.trim() == "Running" {
            info!("Service {} is running...", service);
        } else {
            warn!("Service {} is not running!", service);
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
}

pub fn main(cmd: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let default_path = "./config.json".to_owned();
    let file_path = cmd.get_one::<String>("config").unwrap_or(&default_path);
    let file = File::open(&file_path)?;
    let reader = BufReader::new(file);
    let config: SysConfig = serde_json::from_reader(reader)?;
    if !verify_config(&config) {
        setup::main().unwrap();
    }
    configure_firewall(&config);
    //let password = prompt_password("Enter password for valid users: ").unwrap();
    audit_local_users(&config);
    if yes_no("Check AD Users (Must be on AD Server)".to_owned()) {
        audit_ad_users(&config);
    }
    select_services(&config);
    Ok(())
}
