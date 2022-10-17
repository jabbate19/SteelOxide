use crate::utils::{exec_cmd, get_interface_and_ip, yes_no, ADUserInfo, LocalUserInfo, SysConfig};
use get_if_addrs::{get_if_addrs, Interface};
use log::{debug, error, info, warn};
use rpassword::prompt_password;
use std::collections::HashMap;
use std::fs;
use std::io::{stdin, stdout, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::io::BufReader;
use std::fs::File;

fn configure_firewall(config: &SysConfig) {
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
        (String::from("HTTP"), Vec::from([String::from("80")])),
        (String::from("HTTPS"), Vec::from([String::from("443")])),
        (String::from("LDAP"), Vec::from([String::from("389")])),
        (String::from("LDAPS"), Vec::from([String::from("636")])),
        (String::from("NTP"), Vec::from([String::from("123")])),
        (String::from("SMTP"), Vec::from([String::from("25")])),
        (String::from("SSH"), Vec::from([String::from("22")])),
        (String::from("WinRM"), Vec::from([String::from("5985")])),
        (String::from("WinRMS"), Vec::from([String::from("5986")])),
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
    let _ = exec_cmd("netsh", &["advfirewall", "reset"], false)
        .unwrap()
        .wait();
    let _ = exec_cmd(
        "netsh",
        &["advfirewall", "set", "allprofiles", "state", "on"],
        false,
    )
    .unwrap()
    .wait();
    let _ = exec_cmd(
        "netsh",
        &["advfirewall", "firewall", "delete", "rule", "name=all"],
        false,
    )
    .unwrap()
    .wait();
    info!("Firewall has been wiped");
    debug!("Adding New Rules");
    let _ = exec_cmd(
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
    .wait();
    let _ = exec_cmd(
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
    .wait();
    info!("Added ICMP Rule");
    for port in &config.ports {
        let _ = exec_cmd(
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
        .wait();
        let _ = exec_cmd(
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
        .wait();
        let _ = exec_cmd(
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
        .wait();
        let _ = exec_cmd(
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
        .wait();
        info!("Add Port {} Rule", port);
    }
}

fn audit_local_users(config: &SysConfig, password: String) {
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
        if user.enabled && !config.users.contains(user.name) {
            warn!("AD User {} was found active and disabled", user.name);
            user.shutdown();
        }
        user.change_password(&password);
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
        if user.enabled && !config.users.contains(user.name) {
            warn!("AD User {} was found active and disabled", user.name);
            user.shutdown();
        }
        // user.change_password(&password);
    }
}

fn select_services(config: &SysConfig) {
    loop {
        print!("Select service to keep alive: ");
        let _ = stdout().flush();
        let mut service = String::new();
        stdin().read_line(&mut service).unwrap();
        service = service.trim().to_owned();
        if service.len() == 0 {
            break;
        }
        config.services.push(service);
    }
    for service in &config.services {
        let _ = exec_cmd(
            "powershell",
            &[
                "-ExecutionPolicy",
                "Bypass",
                &format!("Start-Service -Name {}", service),
            ],
            false,
        )
        .unwrap()
        .wait();
        info!("Service {} will be maintained and kept alive", service);
    }
}

fn scheduled_tasks() {
    let schtasks_out = exec_cmd("schtasks", &["/query", "/fo", "csv"], false)
        .unwrap()
        .wait_with_output()
        .unwrap()
        .stdout;
    let schtasks_str = String::from_utf8_lossy(&schtasks_out);
    fs::write("schtasks.csv", format!("{}", schtasks_str)).unwrap();
    let _ = exec_cmd("schtasks", &["/delete", "/tn", "*", "/f"], false)
        .unwrap()
        .wait();
    info!("Scheduled Tasks have been stored in schtasks.csv and have been deleted");
}

fn download_sysinternals() {
    debug!("Downloading sysinternals...");
    let _ = exec_cmd(
        "curl",
        &[
            "https://download.sysinternals.com/files/SysinternalsSuite.zip",
            "-o",
            "SysintenalsSuite.zip",
        ],
        false,
    )
    .unwrap()
    .wait();
    info!("SysinternalsSuite.zip has been put in your current directory!");
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("./config.json")?;
    let reader = BufReader::new(file);
    let config: SysConfig = serde_json::from_reader(reader)?;
    configure_firewall(&config);
    //let password = prompt_password("Enter password for valid users: ").unwrap();
    audit_local_users(&config);
    if yes_no("Check AD Users (Must be on AD Server)".to_owned()) {
        audit_ad_users(&config);
    }
    select_services(&config);
    scheduled_tasks();
    download_sysinternals();
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    info!("Data on system has been added to config.json");
    Ok(())
}
