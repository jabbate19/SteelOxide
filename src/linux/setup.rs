use crate::utils::{exec_cmd, yes_no, SysConfig, UserInfo};
use get_if_addrs::{get_if_addrs, Interface};
use rpassword::prompt_password;
use std::{
    fs,
    io::{stdin, stdout, Write},
    net::{IpAddr, Ipv4Addr},
    process::ExitStatus,
};

fn change_password(user: &str, password: &str) -> ExitStatus {
    let mut proc = exec_cmd("passwd", &[user], true).unwrap();
    proc.stdin
        .as_ref()
        .unwrap()
        .write_all(password.as_bytes())
        .unwrap();
    proc.stdin
        .as_ref()
        .unwrap()
        .write_all(password.as_bytes())
        .unwrap();
    proc.wait().unwrap()
}

fn configure_firewall(config: &mut SysConfig) {
    let mut ports: Vec<u16> = Vec::new();
    let interface_data = get_interface_and_ip();
    println!("{} => {}", interface_data.name, interface_data.ip());
    config.interface = String::from(&interface_data.name);
    config.ip = interface_data.ip();
    let _ = exec_cmd("iptables", &["-F"], false).unwrap().wait();
    let _ = exec_cmd("iptables", &["-t", "mangle", "-F"], false)
        .unwrap()
        .wait();
    let _ = exec_cmd("iptables", &["-P", "INPUT", "DROP"], false)
        .unwrap()
        .wait();
    let _ = exec_cmd("iptables", &["-P", "OUTPUT", "DROP"], false)
        .unwrap()
        .wait();
    let _ = exec_cmd("iptables", &["-P", "FORWARD", "ACCEPT"], false)
        .unwrap()
        .wait();
    let _ = exec_cmd(
        "iptables",
        &["-A", "INPUT", "-p", "imcp", "-j", "ACCEPT"],
        false,
    )
    .unwrap()
    .wait();
    loop {
        print!("Select port to open: ");
        let _ = stdout().flush();
        let mut port_str = String::new();
        stdin().read_line(&mut port_str).unwrap();
        port_str = String::from(port_str.trim());
        if port_str.len() == 0 {
            break;
        }

        match port_str.parse::<u16>() {
            Ok(port) => {
                let _ = exec_cmd(
                    "iptables",
                    &[
                        "-A", "INPUT", "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT",
                    ],
                    false,
                )
                .unwrap()
                .wait();
                let _ = exec_cmd(
                    "iptables",
                    &[
                        "-A", "INPUT", "-p", "udp", "--dport", &port_str, "-j", "ACCEPT",
                    ],
                    false,
                )
                .unwrap()
                .wait();
                let _ = exec_cmd(
                    "iptables",
                    &[
                        "-A", "OUTPUT", "-p", "tcp", "--sport", &port_str, "-j", "ACCEPT",
                    ],
                    false,
                )
                .unwrap()
                .wait();
                let _ = exec_cmd(
                    "iptables",
                    &[
                        "-A", "OUTPUT", "-p", "udp", "--sport", &port_str, "-j", "ACCEPT",
                    ],
                    false,
                )
                .unwrap()
                .wait();
                ports.push(port);
            }
            Err(_) => continue,
        }
    }
    config.ports = ports;
}

fn get_interface_and_ip() -> Interface {
    let ip_a_stdout = exec_cmd("ip", &["a"], false)
        .unwrap()
        .wait_with_output()
        .unwrap()
        .stdout;
    let ip_a_str = String::from_utf8_lossy(&ip_a_stdout);
    loop {
        println!("{}", &ip_a_str);
        print!("Select internet interface: ");
        let _ = stdout().flush();
        let mut interface_name = String::new();
        stdin().read_line(&mut interface_name).unwrap();
        interface_name = interface_name.trim().to_owned();
        match get_if_addrs()
            .unwrap()
            .into_iter()
            .filter(|int| int.name.eq(&interface_name))
            .next()
        {
            Some(ip) => {
                return ip;
            }
            _ => continue,
        }
    }
}

fn audit_users(config: &mut SysConfig) {
    let mut users: Vec<String> = Vec::new();
    let password = prompt_password("Enter password for valid users: ").unwrap();
    for user in UserInfo::get_all_users() {
        if !["/bin/false", "/usr/bin/nologin"].contains(&&user.shell[..]) {
            if yes_no(format!("Keep user {}", &user.username)) {
                users.push(String::from(&user.username));
                change_password(&user.username, &password);
            } else {
                user.shutdown();
            }
            let cron = exec_cmd("crontab", &["-u", &user.username, "-l"], false)
                .unwrap()
                .wait_with_output()
                .unwrap()
                .stdout;
            let cron_str = String::from_utf8_lossy(&cron).to_string();
            fs::write(&format!("cron_{}.json", user.username), cron_str).unwrap();
            if user.uid == 0 {
            } else if user.uid < 1000 {
            }
            if user.gid == 0 {}
        }
    }
    config.users = users;
}

fn select_services(config: &mut SysConfig) {
    let mut services: Vec<String> = Vec::new();
    loop {
        print!("Select service to keep alive: ");
        let _ = stdout().flush();
        let mut service = String::new();
        stdin().read_line(&mut service).unwrap();
        service = String::from(service.trim().trim_end_matches(".service"));
        if service.len() == 0 {
            break;
        }
        let _ = exec_cmd("systemctl", &["enable", &service], false)
            .unwrap()
            .wait();
        let _ = exec_cmd("systemctl", &["start", &service], false)
            .unwrap()
            .wait();
        services.push(service);
    }
    config.services = services;
}

fn sudo_protection() {}

fn sshd_protection() {}

fn scan_file_permissions() {}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = SysConfig {
        ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        interface: String::new(),
        ports: Vec::new(),
        services: Vec::new(),
        users: Vec::new(),
    };
    configure_firewall(&mut config);
    audit_users(&mut config);
    select_services(&mut config);
    sudo_protection();
    sshd_protection();
    scan_file_permissions();
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    Ok(())
}
