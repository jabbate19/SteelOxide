use crate::utils::{exec_cmd, yes_no, Permissions, PfConfig, UserInfo};
use std::collections::HashMap;
use std::env;
use std::fs::{self, read_to_string};
use std::io::{stdin, stdout, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

fn configure_firewall(config: &mut PfConfig) {
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

    print!("Enter IP Subnet of LAN: ");
    let _ = stdout().flush();
    stdin().read_line(&mut config.lan_subnet).unwrap();
    config.lan_subnet = config.lan_subnet.trim().to_owned();

    print!("Enter IP of LAN Interface: ");
    let _ = stdout().flush();
    let mut lan_addr = String::new();
    stdin().read_line(&mut lan_addr).unwrap();
    config.lan_ip = lan_addr.trim().to_owned().parse().unwrap();

    print!("Enter Name of LAN Interface: ");
    let _ = stdout().flush();
    stdin().read_line(&mut config.lan_interface).unwrap();
    config.lan_interface = config.lan_interface.trim().to_owned();

    print!("Enter IP Subnet of WAN: ");
    let _ = stdout().flush();
    stdin().read_line(&mut config.wan_subnet).unwrap();
    config.wan_subnet = config.wan_subnet.trim().to_owned();

    print!("Enter IP of WAN Interface: ");
    let _ = stdout().flush();
    let mut wan_addr = String::new();
    stdin().read_line(&mut wan_addr).unwrap();
    config.wan_ip = wan_addr.trim().to_owned().parse().unwrap();

    print!("Enter Name of WAN Interface: ");
    let _ = stdout().flush();
    stdin().read_line(&mut config.wan_interface).unwrap();
    config.wan_interface = config.wan_interface.trim().to_owned();

    loop {
        let mut perm = Permissions {
            ip: String::new(),
            ports: Vec::new(),
            allow_icmp: false,
        };
        print!("Enter IP Address: ");
        let _ = stdout().flush();
        stdin().read_line(&mut perm.ip).unwrap();
        perm.ip = perm.ip.trim().to_owned();
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
                        perm.ports.push(port);
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
                                perm.ports.push(service_port.to_owned());
                            }
                        }
                        None => {
                            println!("Service Not Found!");
                        }
                    }
                }
            }
        }
        perm.allow_icmp = yes_no("Allow ICMP".to_owned());

        println!("{:?}", perm);
        config.permissions.push(perm);

        if yes_no("Add Another Device".to_owned()) {
            continue;
        } else {
            break;
        }
    }
    let mut output = String::from("block all\n");
    for perm in &config.permissions {
        output.push_str(&format!("\n#### {}\n", perm.ip));
        for port in &perm.ports {
            output.push_str(&format!("\n### Port {}\n", port));
            output.push_str(&format!(
                "pass in quick proto {{ udp tcp }} from any to {} port {{ {} }}\n",
                perm.ip, port
            ));
            output.push_str(&format!(
                "pass out quick proto {{ udp tcp }} from {} to any port {{ {} }}\n",
                perm.ip, port
            ));
        }
        if perm.allow_icmp {
            output.push_str("\n### ICMP\n");
            output.push_str(&format!(
                "pass in quick proto {{ icmp }} from any to {}\n",
                perm.ip
            ));
            output.push_str(&format!(
                "pass out quick proto {{ icmp }} from {} to any\n",
                perm.ip
            ));
        }
    }
    output.push_str("\n#### Common Allows\npass out proto {{ tcp udp }} from any to port {{ 22 53 80 123 443 }}\n");

    output.push_str(&format!(
        "\n#### No SSH :(\nblock in proto {{ tcp udp }} from any to {} port {{ 22 }}\n",
        config.wan_ip
    ));

    if yes_no("Allow SSH to PfSense (Sorry @Drew)".to_owned()) {
        output.push_str("\n#### Allow SSH within Subnet\n");
        output.push_str(&format!(
            "pass in quick proto {{ tcp udp }} from {} to {} port {{ 22 }}\n",
            config.lan_subnet, config.lan_ip
        ));
        output.push_str(&format!(
            "pass out quick proto {{ tcp udp }} from {} port {{ 22 }} to {}\n",
            config.lan_ip, config.lan_subnet
        ));
    } else if yes_no("In that case, want me to just kill SSH all together?".to_owned()) {
        exec_cmd("chmod", &["444", "/etc/sshd"], false)
            .unwrap()
            .wait()
            .unwrap();
        println!("Just make sure to stop it in the pf console");
    }

    output.push_str("\n#### Allow WebConfig\n");
    output.push_str(&format!(
        "pass in quick proto {{ tcp udp }} from {} to {} port {{ 80 }}\n",
        config.lan_subnet, config.lan_ip
    ));
    output.push_str(&format!(
        "pass out quick proto {{ tcp udp }} from {} port {{ 80 }} to {} \n",
        config.lan_ip, config.lan_subnet
    ));

    let _ = exec_cmd("cp", &["/etc/pf.conf", "/root/old_pf.conf"], false);
    fs::write("/etc/pf.conf", output).unwrap();
    let _ = exec_cmd("pfctl", &["-f", "/etc/pf.conf"], false);
}

fn verify_web_config() {
    loop {
        println!(
            "Version: {}",
            match read_to_string("/etc/version") {
                Ok(version) => version,
                Err(_) => String::from("Error getting Version"),
            }
        );
        println!(
            "Patch: {}",
            match read_to_string("/etc/version.patch") {
                Ok(patch) => patch,
                Err(_) => String::from("Error getting Patch"),
            }
        );
        println!("==========");
        println!("All Known Versions:");
        println!("- 2.6.0");
        println!("  - Patch 0");
        println!("- 2.5.2");
        println!("- 2.5.1");
        println!("- 2.5.0");
        print!("Provide pfSense Version, or N/A for Other: ");
        let _ = stdout().flush();
        let mut version = String::new();
        stdin().read_line(&mut version).unwrap();
        match &version[..] {
            "2.6.0" => {
                check_hashes("2_6_0");
                break;
            }
            "2.5.2" => {
                check_hashes("2_5_2");
                break;
            }
            "2.5.1" => {
                check_hashes("2_5_1");
                break;
            }
            "2.5.0" => {
                check_hashes("2_5_0");
                break;
            }
            "N/A" => {
                break;
            }
            _ => {}
        }
    }
}

fn check_hashes(version: &str) {
    let hashes = reqwest::blocking::get(&format!(
        "https://raw.githubusercontent.com/jabbate19/BlueTeamRust/master/data/{}.json",
        version
    ))
    .unwrap()
    .json::<serde_json::Value>()
    .unwrap();
    let current_dir = env::current_dir().unwrap();
    env::set_current_dir(&Path::new("/usr/local/www")).unwrap();
    let all_files_stdout = exec_cmd("find", &["."], false)
        .unwrap()
        .wait_with_output()
        .unwrap()
        .stdout;
    let all_files = String::from_utf8_lossy(&all_files_stdout);
    for file in all_files.split("\n") {
        match hashes.get(file) {
            Some(known_hash) => {
                let new_hash_stdout = exec_cmd("sha1sum", &[file], false)
                    .unwrap()
                    .wait_with_output()
                    .unwrap()
                    .stdout;
                let new_hash = String::from_utf8_lossy(&new_hash_stdout);
                if known_hash != new_hash.split_whitespace().next().unwrap() {
                    println!("Hash for {} does not match key!", file);
                }
            }
            None => {
                println!("{} does not exist in dictionary!", file);
            }
        }
    }
    env::set_current_dir(&current_dir).unwrap();
}

pub fn audit_users(config: &mut PfConfig) {
    for user in UserInfo::get_all_users() {
        if !["/bin/false", "/usr/bin/nologin"].contains(&&user.shell[..]) {
            if yes_no(format!("Keep user {}", &user.username)) {
                config.users.push(String::from(&user.username));
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

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = PfConfig {
        lan_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        lan_subnet: String::new(),
        lan_interface: String::new(),
        wan_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        wan_subnet: String::new(),
        wan_interface: String::new(),
        permissions: Vec::new(),
        users: Vec::new(),
    };
    configure_firewall(&mut config);
    verify_web_config();
    audit_users(&mut config);
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    Ok(())
}
