use crate::utils::{exec_cmd, yes_no, SysConfig, UserInfo};
use get_if_addrs::{get_if_addrs, Interface};
use rpassword::prompt_password;
use std::{
    fs,
    io::{stdin, stdout, Write},
    net::{IpAddr, Ipv4Addr},
    process::ExitStatus,
    collections::HashMap,
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
    for port in &config.ports {
        let _ = exec_cmd(
            "iptables",
            &[
                "-A", "INPUT", "-p", "tcp", "--dport", &port, "-j", "ACCEPT",
            ],
            false,
        )
        .unwrap()
        .wait();
        let _ = exec_cmd(
            "iptables",
            &[
                "-A", "INPUT", "-p", "udp", "--dport", &port, "-j", "ACCEPT",
            ],
            false,
        )
        .unwrap()
        .wait();
        let _ = exec_cmd(
            "iptables",
            &[
                "-A", "OUTPUT", "-p", "tcp", "--sport", &port, "-j", "ACCEPT",
            ],
            false,
        )
        .unwrap()
        .wait();
        let _ = exec_cmd(
            "iptables",
            &[
                "-A", "OUTPUT", "-p", "udp", "--sport", &port, "-j", "ACCEPT",
            ],
            false,
        )
        .unwrap()
        .wait();
    }
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
    let password = prompt_password("Enter password for valid users: ").unwrap();
    for user in UserInfo::get_all_users() {
        if !["/bin/false", "/usr/bin/nologin"].contains(&&user.shell[..]) {
            if yes_no(format!("Keep user {}", &user.username)) {
                config.users.push(String::from(&user.username));
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
                println!("{} has root UID!", user.username);
            } else if user.uid < 1000 {
                println!("{} has admin UID!", user.username);
            }
            if user.gid == 0 {
                println!("{} has root GID!", user.username);
            }
        }
    }
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
