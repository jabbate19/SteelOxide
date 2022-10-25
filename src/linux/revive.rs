use crate::os::setup;
use crate::utils::{
    config::SysConfig,
    tools::{exec_cmd, verify_config},
    user::UserInfo,
};
use clap::ArgMatches;
use log::{debug, error, info, warn};
use std::fs::File;
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
    // let password = prompt_password("Enter password for valid users: ").unwrap();
    for user in UserInfo::get_all_users() {
        println!("{:?}", user);
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
            user.shutdown();
            warn!("Local User {} was found active and disabled", user.username);
        }
        // user.change_password(&password);
        // let cron = exec_cmd("crontab", &["-u", &user.username, "-l"], false)
        //     .unwrap()
        //     .wait_with_output()
        //     .unwrap()
        //     .stdout;
        // let cron_str = String::from_utf8_lossy(&cron).to_string();
        // fs::write(&format!("cron_{}.json", user.username), cron_str).unwrap();
    }
}

fn select_services(config: &SysConfig) {
    for service in &config.services {
        if !exec_cmd("/usr/bin/systemctl", &["status", &service], false)
            .unwrap()
            .wait()
            .unwrap()
            .success()
        {
            warn!("Service {} is not running!", service);
            if !exec_cmd("/usr/bin/systemctl", &["enable", &service], false)
                .unwrap()
                .wait()
                .unwrap()
                .success()
            {
                error!("Failed to enable {}", service);
                continue;
            }
            if !exec_cmd("/usr/bin/systemctl", &["start", &service], false)
                .unwrap()
                .wait()
                .unwrap()
                .success()
            {
                error!("Failed to start {}", service);
                continue;
            }
            info!("Service {} will be maintained and kept alive", service);
        } else {
            info!("Service {} is still running...", service);
        }
    }
}

fn icmp_sysctl_check() {
    let icmp_check = Path::new("/proc/sys/net/ipv4/icmp_echo_ignore_all");
    if fs::read_to_string(icmp_check) == "1" {
        warn!("ICMP Response is Disabled!");
        fs::write(icmp_check, "0");
    }
}

fn sudo_protection() {}

fn sshd_protection() {}

fn scan_file_permissions() {}

pub fn main(cmd: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let default_path = "./config.json".to_owned();
    let file_path = cmd.get_one::<String>("config").unwrap_or(&default_path);
    let file = File::open(&file_path);
    let reader = file.map(|f| BufReader::new(f));
    let config: SysConfig = match reader.map(|r| serde_json::from_reader(r)) {
        Ok(x) => {
            x
        },
        Err(_) => {
            error!("Could not setup config! Moving to setup...");
            setup::main().unwrap();
        }
    };
    if !verify_config(&config) {
        warn!("Config found to be invalid! Moving to setup...");
        setup::main().unwrap();
    }
    configure_firewall(&config);
    audit_users(&config);
    select_services(&config);
    icmp_sysctl_check()
    sudo_protection();
    sshd_protection();
    scan_file_permissions();
    Ok(())
}
