use crate::os::setup;
use crate::utils::{
    config::PfConfig,
    tools::{exec_cmd, sha1sum, verify_config, yes_no},
    user::UserInfo,
};
use log::{error, info, warn};
use serde_json::Value;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use clap::ArgMatches;

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

fn verify_web_config(config: &PfConfig) {
    let hashes = reqwest::blocking::get(
        "https://raw.githubusercontent.com/jabbate19/BlueTeamRust/master/data/pfsense_webconfig.json"
    )
    .unwrap()
    .json::<serde_json::Value>()
    .unwrap();
    check_hashes_find_files(
        &Path::new("/usr/local/www"),
        &hashes,
        match &config.version.as_ref() {
            Some(version) => {
                version.to_owned()
            },
            None => {
                error!("Version is not available to verify files");
                return;
            }
        }
    );
    check_hashes_check_files(
        &Path::new("/usr/local/www"),
        &hashes,
        match &config.version.as_ref() {
            Some(version) => {
                version.to_owned()
            },
            None => {
                error!("Version is not available to verify files");
                return;
            }
        }
    );
}

fn verity_etc_files(config: &PfConfig) {
    let hashes = reqwest::blocking::get(
        "https://raw.githubusercontent.com/jabbate19/BlueTeamRust/master/data/pfsense_etc.json",
    )
    .unwrap()
    .json::<serde_json::Value>()
    .unwrap();
    check_hashes_check_files(
        &Path::new("/etc"),
        &hashes,
        match &config.version.as_ref() {
            Some(version) => {
                version.to_owned()
            },
            None => {
                error!("Version is not available to verify files");
                return;
            }
        }
    );
}

fn check_hashes_find_files(dir: &Path, hashes: &Value, version: &str) {
    let current_dir = env::current_dir().unwrap();
    env::set_current_dir(dir).unwrap();
    let all_files_cmd = exec_cmd("find", &[".", "-type", "f"], false)
        .unwrap()
        .wait_with_output()
        .unwrap();
    let all_files_stdout = match all_files_cmd.status.success() {
        true => all_files_cmd.stdout,
        false => {
            error!("Failed to recursively find all files in {}", dir.display());
            return;
        }
    };
    let all_files = String::from_utf8_lossy(&all_files_stdout);
    let hashes = hashes.get(version).unwrap();
    for file in all_files.split("\n") {
        match hashes.get(file) {
            Some(known_hash) => match sha1sum(file.to_string()) {
                Ok(new_hash) => {
                    if known_hash.as_str().unwrap().to_owned() != new_hash {
                        warn!("Hash for {} does not match key!", file);
                        let diff_cmd = exec_cmd("diff", &[file, &get_fixed_file(file.to_string(), version)], false)
                        .unwrap()
                        .wait_with_output()
                        .unwrap();
                        let diff_stdout = match diff_cmd.status.success() {
                            true => diff_cmd.stdout,
                            false => {
                                error!("Failed to diff new and old files for {}", file);
                                continue;
                            }
                        };
                        let diff = String::from_utf8_lossy(&diff_stdout);
                        warn!("{}", diff);
                    }
                }
                Err(_) => {
                    error!("Failed to sha1sum {}", file);
                }
            },
            None => {
                warn!("{} does not exist in dictionary!", file);
            }
        }
    }
    env::set_current_dir(&current_dir).unwrap();
}

fn check_hashes_check_files(dir: &Path, hashes: &Value, version: &str) {
    let current_dir = env::current_dir().unwrap();
    env::set_current_dir(dir).unwrap();
    let hashes = hashes.get(version).unwrap();
    for (file, known_hash) in hashes.as_object().unwrap() {
        match sha1sum(file.to_string()) {
            Ok(new_hash) => {
                if known_hash.as_str().unwrap().to_owned() != new_hash {
                    warn!("Hash for {} does not match key!", file);
                    let diff_cmd = exec_cmd("diff", &[file, &get_fixed_file(file.to_string(), version)], false)
                        .unwrap()
                        .wait_with_output()
                        .unwrap();
                    let diff_stdout = match diff_cmd.status.success() {
                        true => diff_cmd.stdout,
                        false => {
                            error!("Failed to diff new and old files for {}", file);
                            continue;
                        }
                    };
                    let diff = String::from_utf8_lossy(&diff_stdout);
                    warn!("{}", diff);
                }
            }
            Err(_) => {
                error!("Hash for {} had an error (Likely doesn't exist)!", file);
                error!("Putting replacement file in {}", get_fixed_file(file.to_string(), version));
            }
        }
    }
    env::set_current_dir(&current_dir).unwrap();
}

fn get_fixed_file(mut file: String, version: &str) -> String {
    if ["2_2", "2_1", "2_0", "1_2"].contains(&&version[..]) {
        file = format!("src/{}", file);
    }
    let git_version = format!("RELENG_{}", version);
    let new_file_name = format!("new_{}", file.split('/').last().unwrap());
    let hashes = reqwest::blocking::get(&format!(
        "https://raw.githubusercontent.com/pfsense/pfsense/{}/{}",
        git_version, file
    ))
    .unwrap()
    .bytes()
    .unwrap();
    let mut out_file = File::open(&new_file_name).unwrap_or(File::create(&new_file_name).unwrap());
    out_file.write(&hashes).unwrap();
    new_file_name
}

fn audit_users(config: &PfConfig) {
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
    verity_etc_files(&config);
    fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    info!("Data on system has been added to config.json");
    Ok(())
}
