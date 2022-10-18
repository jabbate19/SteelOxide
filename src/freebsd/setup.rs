use crate::os::core::{verify_web_config, verity_etc_files};
use crate::utils::{
    config::{Permissions, PfConfig},
    tools::{exec_cmd, get_interface_and_ip, yes_no},
    user::UserInfo,
};
use log::{error, info, warn};
use rpassword::prompt_password;
use std::collections::HashMap;
use std::fs::{self, read_to_string};
use std::io::{stdin, stdout, Write};
use std::net::{IpAddr, Ipv4Addr};

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

    println!("LAN INTERFACE");

    let lan_interface_data = get_interface_and_ip();

    config.lan_interface = String::from(&lan_interface_data.name);

    config.lan_ip = lan_interface_data.ip();

    print!("Enter CIDR of LAN: ");
    let _ = stdout().flush();
    stdin().read_line(&mut config.lan_subnet).unwrap();
    config.lan_subnet = config.lan_subnet.trim().to_owned();

    info!(
        "LAN on {} | {}/{}",
        config.lan_interface, config.lan_ip, config.lan_subnet
    );

    println!("WAN INTERFACE");

    let wan_interface_data = get_interface_and_ip();

    config.wan_interface = String::from(&wan_interface_data.name);

    config.wan_ip = wan_interface_data.ip();

    print!("Enter CIDR of WAN: ");
    let _ = stdout().flush();
    stdin().read_line(&mut config.wan_subnet).unwrap();
    config.wan_subnet = config.wan_subnet.trim().to_owned();

    info!(
        "WAN on {} | {}/{}",
        config.wan_interface, config.wan_ip, config.wan_subnet
    );

    if yes_no("Add DMZ".to_owned()) {
        println!("DMZ INTERFACE");

        let dmz_interface_data = get_interface_and_ip();

        config.dmz_interface = Some(String::from(&dmz_interface_data.name));

        config.dmz_ip = Some(dmz_interface_data.ip());

        print!("Enter CIDR of DMZ: ");
        let mut dmz_sub = String::new();
        let _ = stdout().flush();
        stdin().read_line(&mut dmz_sub).unwrap();
        config.dmz_subnet = Some(dmz_sub.trim().to_owned());

        info!(
            "DMZ on {} | {}/{}",
            config.dmz_interface.as_ref().unwrap(),
            config.dmz_ip.as_ref().unwrap(),
            config.dmz_subnet.as_ref().unwrap()
        );
    }

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
        {
            let _ip_test: Ipv4Addr = match &perm.ip.parse() {
                Ok(x) => *x,
                Err(_) => continue,
            };
        }
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
            info!("Allowing traffic to/from {} on port {}", perm.ip, port);
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
            info!("Allowing ICMP to Device");
        }
    }
    output.push_str("\n#### Common Allows\n");
    output.push_str("pass out proto {{ tcp udp }} from any to any port {{ 22 53 80 123 443 }}\n");
    output.push_str("pass in proto {{ tcp udp }} from any port {{ 22 53 80 123 443 }} to any\n");

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
        info!("Allowing SSH to Router");
    } else {
        output.push_str(&format!(
            "\n#### No SSH :(\nblock in proto {{ tcp udp }} from any to {} port {{ 22 }}\n",
            config.wan_ip
        ));
        info!("Blocking SSH to Router");
        if yes_no("In that case, want me to just kill SSH all together?".to_owned()) {
            let sshd_chmod = exec_cmd("chmod", &["444", "/etc/sshd"], false)
                .unwrap()
                .wait()
                .unwrap();
            if sshd_chmod.success() {
                info!("Disabled /etc/sshd");
            } else {
                error!("Failed to chmod /etc/sshd");
            }

            println!("Just make sure to stop it in the pf console");
        }
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
    info!("Added rules for webconfig");

    let cp_old = exec_cmd("cp", &["/etc/pf.conf", "/root/old_pf.conf"], false)
        .unwrap()
        .wait()
        .unwrap();
    if cp_old.success() {
        fs::write("/etc/pf.conf", output).unwrap();
        let set_rules = exec_cmd("pfctl", &["-f", "/etc/pf.conf"], false)
            .unwrap()
            .wait()
            .unwrap();
        if set_rules.success() {
            info!("Rules have been applied to system!");
        } else {
            error!("Error in applying rules");
        }
    } else {
        error!("Error in copying old pf.conf");
        fs::write("./new_pf.conf", output).unwrap();
        error!("New pf.conf saved as ./new_pf.conf");
    }
}

fn get_version(config: &mut PfConfig) {
    let versions = [
        "2_6_0", "2_5_2", "2_5_1", "2_5_0", "2_4_5", "2_4_4", "2_4_3", "2_4_2", "2_4_1", "2_4_0",
        "2_3_5", "2_3_4", "2_3_3", "2_3_2", "2_3_1", "2_3_0", "2_2", "2_1", "2_0", "1_2",
    ];

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
        print!("Provide pfSense Version, or N/A for Other: ");
        let _ = stdout().flush();
        let mut version = String::new();
        stdin().read_line(&mut version).unwrap();
        if versions.contains(&&version[..]) {
            info!("PfSense version identifed as {}", version);
            config.version = Some(version);
        } else if version == "N/A" {
            break;
        }
    }
}

fn audit_users(config: &mut PfConfig) {
    let password = prompt_password("Enter password for users: ").unwrap();
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
        let cron_cmd = exec_cmd("crontab", &["-u", &user.username, "-l"], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        let cron_stdout = match cron_cmd.status.success() {
            true => cron_cmd.stdout,
            false => {
                error!("Failed to get cron jobs for {}", user.username);
                continue;
            }
        };
        let cron_str = String::from_utf8_lossy(&cron_stdout).to_string();
        fs::write(&format!("cron_{}.json", user.username), cron_str).unwrap();
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
        dmz_ip: None,
        dmz_subnet: None,
        dmz_interface: None,
        version: None,
        permissions: Vec::new(),
        users: Vec::new(),
    };
    configure_firewall(&mut config);
    audit_users(&mut config);
    get_version(&mut config);
    verify_web_config(&config);
    verity_etc_files(&config);
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    info!("Data on system has been added to config.json");
    Ok(())
}
