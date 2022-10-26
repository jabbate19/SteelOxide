use crate::os::core::{icmp_sysctl_check, scan_file_permissions, sshd_protection, sudo_protection};
use crate::utils::{
    config::SysConfig,
    tools::{exec_cmd, get_interface_and_ip, get_password, sha1sum_vec, yes_no},
    user::UserInfo,
};
use log::{debug, error, info, warn};
use std::{
    collections::HashMap,
    fs,
    io::{stdin, stdout, Write},
    net::{IpAddr, Ipv4Addr},
};

fn configure_firewall(config: &mut SysConfig) {
    let default_services: HashMap<String, Vec<String>> = HashMap::from([
        (
            String::from("AD"),
            Vec::from([
                String::from("389"),
                String::from("445"),
                String::from("88"),
                String::from("135"),
                String::from("3268"),
                String::from("123"),
            ]),
        ),
        (String::from("DNS"), Vec::from([String::from("53")])),
        (
            String::from("HTTP"),
            Vec::from([String::from("80"), String::from("443")]),
        ),
        (
            String::from("LDAP"),
            Vec::from([String::from("389"), String::from("636")]),
        ),
        (String::from("NTP"), Vec::from([String::from("123")])),
        (String::from("SMTP"), Vec::from([String::from("25")])),
        (String::from("SSH"), Vec::from([String::from("22")])),
        (
            String::from("WinRM"),
            Vec::from([String::from("5985"), String::from("5986")]),
        ),
    ]);
    let interface_data = get_interface_and_ip();
    println!("{} => {}", interface_data.name, interface_data.ip());
    config.interface = String::from(&interface_data.name);
    config.ip = interface_data.ip();
    loop {
        let mut port = String::new();
        print!("Enter Port/Common Service to Allow, '?', or nothing to stop: ");
        let _ = stdout().flush();
        stdin().read_line(&mut port).unwrap();
        port = port.trim().to_owned();
        if port.len() == 0 {
            break;
        }
        match port.parse::<u16>() {
            Ok(num) => {
                if num > 0 {
                    config.ports.push(port);
                } else {
                    println!("Invalid Number!");
                }
            }
            Err(_) => {
                if port.chars().next().unwrap() == '?' {
                    for (service, ports) in &default_services {
                        println!("{} - {:?}", service, ports);
                    }
                    continue;
                }
                match default_services.get(&port) {
                    Some(service_ports) => {
                        for service_port in service_ports {
                            config.ports.push(service_port.to_owned());
                        }
                    }
                    None => {
                        println!("Service Not Found!");
                    }
                }
            }
        }
    }
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
    if !exec_cmd(
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
    if !exec_cmd(
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

    let fw_cmd = exec_cmd("/usr/sbin/iptables", &["-L"], false)
        .unwrap()
        .wait_with_output()
        .unwrap();
    let mut fw_stdout = fw_cmd.stdout;

    let fw_mangle_cmd = exec_cmd("/usr/sbin/iptables", &["-t", "MANGLE", "-L"], false)
        .unwrap()
        .wait_with_output()
        .unwrap();
    let mut fw_mangle_stdout = fw_mangle_cmd.stdout;

    fw_stdout.append(&mut fw_mangle_stdout);

    config.firewall_hash = sha1sum_vec(&fw_stdout).unwrap();
}

fn audit_users(config: &mut SysConfig) {
    let password = get_password();
    for user in UserInfo::get_all_users() {
        if user.uid == 0 {
            warn!("{} has root UID!", user.username);
        } else if user.uid < 1000 {
            warn!("{} has admin UID!", user.username);
        }
        if user.gid == 0 {
            warn!("{} has root GID!", user.username);
        }
        info!("{:?}", user);
        if !["/bin/false", "/usr/bin/nologin"].contains(&&user.shell[..]) {
            if yes_no(format!("Keep user {}", &user.username)) {
                config.users.push(String::from(&user.username));
                info!("Local User {} was found and kept", user.username);
            } else {
                user.shutdown();
                info!("Local User {} was found and disabled", user.username);
            }
        }
        user.change_password(&password);
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

fn select_services(config: &mut SysConfig) {
    loop {
        print!("Select service to keep alive: ");
        let _ = stdout().flush();
        let mut service = String::new();
        stdin().read_line(&mut service).unwrap();
        service = String::from(service.trim().trim_end_matches(".service"));
        if service.len() == 0 {
            break;
        }
        config.services.push(service);
    }
    for service in &config.services {
        let enable = exec_cmd("/usr/bin/systemctl", &["enable", &service], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        if !enable.status.success() {
            error!(
                "Failed to enable {}: {}",
                service,
                String::from_utf8_lossy(&enable.stderr)
            );
            continue;
        }
        let start = exec_cmd("/usr/bin/systemctl", &["start", &service], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        if !start.status.success() {
            error!(
                "Failed to enable {}: {}",
                service,
                String::from_utf8_lossy(&start.stderr)
            );
            continue;
        }
        info!("Service {} will be maintained and kept alive", service);
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = SysConfig {
        ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        interface: String::new(),
        ports: Vec::new(),
        services: Vec::new(),
        users: Vec::new(),
        firewall_hash: String::new(),
    };
    configure_firewall(&mut config);
    audit_users(&mut config);
    select_services(&mut config);
    sudo_protection();
    sshd_protection();
    scan_file_permissions();
    icmp_sysctl_check();
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    info!("Data on system has been added to config.json");
    Ok(())
}
