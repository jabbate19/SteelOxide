use crate::os::setup;
use crate::utils::{
    config::SysConfig,
    tools::{exec_cmd, sha1sum_vec, verify_config, yes_no, get_password},
    user::{ADUserInfo, LocalUserInfo},
};
use clap::ArgMatches;
use log::{debug, error, info, warn};
use std::fs::{self, File};
use std::io::BufReader;

fn check_firewall(config: &SysConfig) {
    let fw_cmd = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "firewall", "show", "rule", "name=all"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();

    let fw_on_cmd = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "show", "currentprofile", "firewallpolicy"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();

    if fw_cmd.status.success() && fw_on_cmd.status.success() {
        let mut fw_stdout = fw_cmd.stdout;
        let mut fw_on_stdout = fw_on_cmd.stdout;
        fw_stdout.append(&mut fw_on_stdout);
        let hash = sha1sum_vec(&fw_stdout).unwrap();
        if hash != config.firewall_hash {
            warn!("Firewall was tampered!");
            warn!("{}", String::from_utf8_lossy(&fw_stdout));
            configure_firewall(&config);
        }
    } else {
        error!("Failed to get firewall!");
    }
}

fn configure_firewall(config: &SysConfig) {
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
    let off = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "set", "allprofiles", "state", "off"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    if !off.status.success() {
        error!(
            "Failed to turn off firewalls: {}",
            String::from_utf8_lossy(&off.stderr)
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
    let on = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "set", "allprofiles", "state", "off"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    if !on.status.success() {
        error!(
            "Failed to turn off firewalls: {}",
            String::from_utf8_lossy(&on.stderr)
        );
    };
}

fn audit_local_users(config: &SysConfig) {
    let password = get_password();
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
            if !yes_no(format!("Keep user {}", &user.name)) {
                user.shutdown();
                info!("AD User {} was found and disabled", user.name);
            }
        }
        if yes_no(format!("Change password for {}", &user.name)) {
            user.change_password(&password);
        }
    }
}

fn audit_ad_users(config: &SysConfig) {
    let password = get_password();
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
            if !yes_no(format!("Keep user {}", &user.name)) {
                user.shutdown();
                info!("AD User {} was found active and disabled", user.name);
            }
        }
        if yes_no(format!("Change password for {}", &user.name)) {
            user.change_password(&password);
        }
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

fn scheduled_tasks() {
    let schtasks_cmd = exec_cmd(
        "C:\\Windows\\System32\\schtasks.exe",
        &["/query", "/fo", "csv"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let schtasks_out = match schtasks_cmd.status.success() {
        true => schtasks_cmd.stdout,
        false => {
            error!("Failed to get scheduled tasks!");
            return;
        }
    };
    let schtasks_str = String::from_utf8_lossy(&schtasks_out);

    match fs::write("schtasks.csv", format!("{}", schtasks_str)) {
        Ok(_) => {
            info!("Scheduled Tasks have been stored in schtasks.csv");
        }
        Err(_) => {
            error!("Failed to write schtasks.csv");
            error!("{}", schtasks_str);
        }
    };
    if exec_cmd(
        "powershell",
        &[
            "-ExecutionPolicy",
            "Bypass",
            &format!("Get-ScheduledTask | Unregister-ScheduledTask -Confirm:$false"),
        ],
        false,
    )
    .unwrap()
    .wait()
    .unwrap()
    .success()
    {
        info!("Scheduled Tasks have been deleted");
    } else {
        error!("Failed to delete all tasks!");
    };
}

fn download_sysinternals() {
    let allow_all = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &[
            "advfirewall",
            "set",
            "currentprofile",
            "firewallpolicy",
            "allowinbound,allowoutbound",
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    if !allow_all.status.success() {
        error!(
            "Failed to allow firewall in/out: {}",
            String::from_utf8_lossy(&allow_all.stderr)
        );
    };

    debug!("Downloading sysinternals...");
    if !exec_cmd(
        "C:\\Windows\\System32\\curl.exe",
        &[
            "https://download.sysinternals.com/files/SysinternalsSuite.zip",
            "-o",
            "SysintenalsSuite.zip",
        ],
        false,
    )
    .unwrap()
    .wait()
    .unwrap()
    .success()
    {
        error!("Failed to download sysinternals!");
        return;
    };
    info!("SysinternalsSuite.zip has been put in your current directory!");

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
}

pub fn main(cmd: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let default_path = "./config.json".to_owned();
    let file_path = cmd.get_one::<String>("config").unwrap_or(&default_path);
    let file = File::open(&file_path)?;
    let reader = BufReader::new(file);
    let config: SysConfig = match serde_json::from_reader(reader) {
        Ok(x) => x,
        Err(_) => {
            error!("Could not setup config! Moving to setup...");
            return setup::main();
        }
    };
    check_firewall(&config);
    //let password = prompt_password("Enter password for valid users: ").unwrap();
    audit_local_users(&config);
    if yes_no("Check AD Users (Must be on AD Server)".to_owned()) {
        audit_ad_users(&config);
    }
    scheduled_tasks();
    download_sysinternals();
    //select_services(&config);
    Ok(())
}
