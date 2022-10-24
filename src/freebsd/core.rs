use crate::utils::{
    config::PfConfig,
    tools::{exec_cmd, sha1sum},
};
use log::{error, warn};
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn verify_web_config(config: &PfConfig) {
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
            Some(version) => version.to_owned(),
            None => {
                error!("Version is not available to verify files");
                return;
            }
        },
    );
    check_hashes_check_files(
        &Path::new("/usr/local/www"),
        &hashes,
        match &config.version.as_ref() {
            Some(version) => version.to_owned(),
            None => {
                error!("Version is not available to verify files");
                return;
            }
        },
    );
}

pub fn verity_etc_files(config: &PfConfig) {
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
            Some(version) => version.to_owned(),
            None => {
                error!("Version is not available to verify files");
                return;
            }
        },
    );
}

pub fn check_hashes_find_files(dir: &Path, hashes: &Value, version: &str) {
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
                        let diff_cmd = exec_cmd(
                            "diff",
                            &[file, &get_fixed_file(file.to_string(), version)],
                            false,
                        )
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

pub fn check_hashes_check_files(dir: &Path, hashes: &Value, version: &str) {
    let current_dir = env::current_dir().unwrap();
    env::set_current_dir(dir).unwrap();
    let hashes = hashes.get(version).unwrap();
    for (file, known_hash) in hashes.as_object().unwrap() {
        match sha1sum(file.to_string()) {
            Ok(new_hash) => {
                if known_hash.as_str().unwrap().to_owned() != new_hash {
                    warn!("Hash for {} does not match key!", file);
                    let diff_cmd = exec_cmd(
                        "diff",
                        &[file, &get_fixed_file(file.to_string(), version)],
                        false,
                    )
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
                error!(
                    "Putting replacement file in {}",
                    get_fixed_file(file.to_string(), version)
                );
            }
        }
    }
    env::set_current_dir(&current_dir).unwrap();
}

pub fn verify_main_config() {
    let diff_cmd = exec_cmd(
        "diff",
        &["/cf/conf/config.xml", &get_fixed_file("/conf.default/config.xml".to_string(), version)],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let diff_stdout = match diff_cmd.status.success() {
        true => diff_cmd.stdout,
        false => {
            error!("Failed to diff new and old files for config.xml");
            continue;
        }
    };
    let diff = String::from_utf8_lossy(&diff_stdout);
    info!("config.xml diff");
    info!("{}", diff);
}

pub fn get_fixed_file(mut file: String, version: &str) -> String {
    if !["2_2", "2_1", "2_0", "1_2"].contains(&version) {
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
