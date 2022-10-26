use crate::os::core::{verify_main_config, verify_web_config, verity_etc_files, sshd_protection, scan_file_permissions};
use crate::os::setup;
use crate::utils::{
    config::PfConfig,
    tools::{exec_cmd, verify_config, yes_no},
    user::UserInfo,
};
use clap::ArgMatches;
use log::{error, info, warn};
use std::fs;
use std::fs::File;
use std::io::BufReader;

fn configure_firewall(config: &PfConfig) {
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
    output.push_str("pass out proto { tcp udp } from any to any port { 22 53 80 123 443 }\n");
    output.push_str("pass in proto { tcp udp } from any port { 22 53 80 123 443 } to any\n");

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
            let sshd_chmod = exec_cmd("/bin/chmod", &["444", "/etc/sshd"], false)
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

    let cp_old = exec_cmd("/bin/cp", &["/etc/pf.conf", "/root/old_pf.conf"], false)
        .unwrap()
        .wait()
        .unwrap();
    if cp_old.success() {
        fs::write("/etc/pf.conf", output).unwrap();
        let set_rules = exec_cmd("/sbin/pfctl", &["-f", "/etc/pf.conf"], false)
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

fn audit_users(config: &PfConfig) {
    // let password = prompt_password("Enter password for valid users: ").unwrap();
    for user in UserInfo::get_all_users() {
        info!("{:?}", user);
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
    }
}

pub fn main(cmd: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let default_path = "./config.json".to_owned();
    let file_path = cmd.get_one::<String>("config").unwrap_or(&default_path);
    let file = File::open(&file_path)?;
    let reader = BufReader::new(file);
    let config: PfConfig = serde_json::from_reader(reader)?;
    if !verify_config(&config) {
        setup::main().unwrap();
    }
    configure_firewall(&config);
    audit_users(&config);
    verify_web_config(&config);
    // verity_etc_files(&config);
    verify_main_config(&config);
    sshd_protection();
    scan_file_permissions();
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    info!("Data on system has been added to config.json");
    Ok(())
}
