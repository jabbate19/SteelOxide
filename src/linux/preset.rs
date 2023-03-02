use crate::os::core::{icmp_sysctl_check, scan_file_permissions, sshd_protection, sudo_protection};
use crate::os::setup;
use crate::utils::tools::{yes_no, get_password};
use crate::utils::{
    config::SysConfig,
    tools::{exec_cmd, sha1sum_vec, verify_config},
    user::UserInfo,
};
use clap::ArgMatches;
use log::{debug, error, info, warn};
use std::fs::{File, self};
use std::io::BufReader;

fn configure_firewall(config: &SysConfig) {
    debug!("Resetting Firewall and deleting old rules");
    if !exec_cmd("/usr/sbin/iptables", &["-F"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to flush iptables");
    };
    if !exec_cmd("/usr/sbin/iptables", &["-t", "mangle", "-F"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to flush iptables mangle table");
    };
    if !exec_cmd("/usr/sbin/iptables", &["-P", "INPUT", "DROP"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to set default iptables input to drop");
    };
    if !exec_cmd("/usr/sbin/iptables", &["-P", "OUTPUT", "DROP"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to set default iptables output to drop");
    };
    if !exec_cmd("/usr/sbin/iptables", &["-P", "FORWARD", "ACCEPT"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to set default iptables forward to accept");
    };
    info!("Firewall has been wiped");
    if exec_cmd(
        "/usr/sbin/iptables",
        &["-A", "INPUT", "-p", "imcp", "-j", "ACCEPT"],
        false,
    )
    .unwrap()
    .wait()
    .unwrap()
    .success()
    {
        info!("Added ICMP Rule");
    } else {
        error!("Failed to add ICMP INPUT ACCEPT rule");
    }
    for port in &config.ports {
        if !exec_cmd(
            "/usr/sbin/iptables",
            &["-A", "INPUT", "-p", "tcp", "--dport", &port, "-j", "ACCEPT"],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to set INPUT ACCEPT TCP PORT {} rule", port);
            continue;
        }
        if !exec_cmd(
            "/usr/sbin/iptables",
            &["-A", "INPUT", "-p", "udp", "--dport", &port, "-j", "ACCEPT"],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to set INPUT ACCEPT UDP PORT {} rule", port);
            continue;
        }
        if !exec_cmd(
            "/usr/sbin/iptables",
            &[
                "-A", "OUTPUT", "-p", "tcp", "--sport", &port, "-j", "ACCEPT",
            ],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to set OUTPUT ACCEPT TCP PORT {} rule", port);
            continue;
        }
        if !exec_cmd(
            "/usr/sbin/iptables",
            &[
                "-A", "OUTPUT", "-p", "udp", "--sport", &port, "-j", "ACCEPT",
            ],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to set OUTPUT ACCEPT UDP PORT {} rule", port);
            continue;
        }
        info!("Add Port {} Rule", port);
    }
}

fn audit_users(config: &SysConfig) {
    let password = get_password();
    // let password = prompt_password("Enter password for valid users: ").unwrap();
    for user in UserInfo::get_all_users() {
        if user.uid == 0 {
            warn!("{} has root UID!", user.username);
        } else if user.uid < 1000 {
            warn!("{} has admin UID!", user.username);
        }
        if user.gid == 0 {
            warn!("{} has root GID!", user.username);
        }
        if !(["/bin/false", "/usr/bin/nologin"].contains(&&user.shell[..])
            || config.users.contains(&user.username))
        {
            if !yes_no(format!("Keep user {}", &user.username)) {
                user.shutdown();
                info!("Local User {} was found and disabled", user.username);
            }
        }
        if yes_no(format!("Change password for {}", &user.username)) {
            user.change_password(&password);
        }
        let cron_cmd = exec_cmd("/usr/bin/crontab", &["-u", &user.username, "-l"], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        let cron_stdout = match cron_cmd.status.success() {
            true => cron_cmd.stdout,
            false => {
                error!(
                    "Failed to get cron jobs for {}: {}",
                    user.username,
                    String::from_utf8_lossy(&cron_cmd.stderr)
                );
                continue;
            }
        };
        let cron_str = String::from_utf8_lossy(&cron_stdout).to_string();
        fs::write(&format!("cron_{}.json", user.username), cron_str).unwrap();
    }
}

pub fn main(cmd: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let default_path = "./config.json".to_owned();
    let file_path = cmd.get_one::<String>("config").unwrap_or(&default_path);
    let file = File::open(&file_path);
    let reader = file.map(|f| BufReader::new(f));
    let config: SysConfig = match reader.map(|r| serde_json::from_reader(r)) {
        Ok(x) => match x {
            Ok(y) => y,
            Err(_) => {
                error!("Could not setup config! Moving to setup...");
                return setup::main();
            }
        },
        Err(_) => {
            error!("Could not setup config! Moving to setup...");
            return setup::main();
        }
    };
    configure_firewall(&config);
    audit_users(&config);
    //select_services(&config);
    //icmp_sysctl_check();
    //sudo_protection();
    //sshd_protection();
    //scan_file_permissions();
    Ok(())
}
