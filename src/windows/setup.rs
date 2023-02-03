use crate::utils::{
    config::SysConfig,
    tools::{exec_cmd, get_interface_and_ip, get_password, sha1sum, sha1sum_vec, yes_no},
    user::{ADUserInfo, LocalUserInfo},
};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::io::{stdin, stdout, Write};
use std::net::{IpAddr, Ipv4Addr};

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

    let fw_cmd = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "firewall", "show", "rule", "name=all"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let mut fw_stdout = fw_cmd.stdout;

    let fw_on_cmd = exec_cmd(
        "C:\\Windows\\System32\\netsh.exe",
        &["advfirewall", "show", "currentprofile", "firewallpolicy"],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let mut fw_on_stdout = fw_on_cmd.stdout;
    fw_stdout.append(&mut fw_on_stdout);

    config.firewall_hash = sha1sum_vec(&fw_stdout).unwrap();
}

fn audit_local_users(config: &mut SysConfig, password: &String) {
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
        if user.enabled {
            if yes_no(format!("Keep user {}", &user.name)) {
                config.users.push(String::from(&user.name));
                info!("Local User {} was found and kept", user.name);
            } else {
                user.shutdown();
                info!("Local User {} was found and disabled", user.name);
            }
        }
        user.change_password(&password);
    }
}

fn audit_ad_users(config: &mut SysConfig, password: &String) {
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
        if user.enabled {
            if yes_no(format!("Keep user {}", &user.name)) {
                config.users.push(String::from(&user.name));
                info!("AD User {} was found and kept", user.name);
            } else {
                user.shutdown();
                info!("AD User {} was found and disabled", user.name);
            }
        }
        if yes_no(format!("Change password for {}", &user.name)) {
            user.change_password(&password);
        }
    }
}

fn select_services(config: &mut SysConfig) {
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
    let password = get_password();
    audit_local_users(&mut config, &password);
    if yes_no("Check AD Users (Must be on AD Server)".to_owned()) {
        audit_ad_users(&mut config, &password);
    }
    select_services(&mut config);
    scheduled_tasks();
    download_sysinternals();
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    info!("Data on system has been added to config.json");
    info!("Your config has is {} REMEMBER THIS", sha1sum("config.json".to_string()).unwrap());
    Ok(())
}
