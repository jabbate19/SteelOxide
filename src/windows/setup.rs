use crate::utils::{yes_no, ADUserInfo, LocalUserInfo, SysConfig};
use rpassword::prompt_password;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};

fn audit_users(config: &mut SysConfig) {
    let password = prompt_password("Enter password for valid users: ").unwrap();
    for user in ADUserInfo::get_all_users() {
        if user.enabled {
            if yes_no(format!("Keep user {}", &user.name)) {
                config.users.push(String::from(&user.name));
            } else {
                user.shutdown();
            }
        }
        user.change_password(&password);
        if user.groups.contains(&"Domain Admins".to_owned()) {
            println!("{} is a Domain Admin!", user.name);
        }
        if user.groups.contains(&"Schema Admins".to_owned()) {
            println!("{} is a Schema Admin!", user.name);
        }
        if user.groups.contains(&"Enterprise Admins".to_owned()) {
            println!("{} is an Enterprise Admin!", user.name);
        }
        if user.groups.contains(&"Administrators".to_owned()) {
            println!("{} is an administrator!", user.name);
        }
    }

    for user in LocalUserInfo::get_all_users() {
        if user.enabled {
            if yes_no(format!("Keep user {}", &user.name)) {
                config.users.push(String::from(&user.name));
            } else {
                user.shutdown();
            }
        }
        user.change_password(&password);
        if user.groups.contains(&"Domain Admins".to_owned()) {
            println!("{} is a Domain Admin!", user.name);
        }
        if user.groups.contains(&"Schema Admins".to_owned()) {
            println!("{} is a Schema Admin!", user.name);
        }
        if user.groups.contains(&"Enterprise Admins".to_owned()) {
            println!("{} is an Enterprise Admin!", user.name);
        }
        if user.groups.contains(&"Administrators".to_owned()) {
            println!("{} is an administrator!", user.name);
        }
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = SysConfig {
        ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        interface: String::new(),
        ports: Vec::new(),
        services: Vec::new(),
        users: Vec::new(),
    };
    audit_users(&mut config);
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    Ok(())
}
