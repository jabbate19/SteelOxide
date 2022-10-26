use crate::utils::{
    config::PfConfig,
    tools::{exec_cmd, sha1sum, yes_no},
};
use log::{error, info, warn};
use serde_json::Value;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
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
        Some("*.php"),
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
        Some("*.php"),
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
        None,
    );
}

pub fn check_hashes_find_files(
    dir: &Path,
    hashes: &Value,
    version: &str,
    name_filter: Option<&str>,
) {
    let current_dir = env::current_dir().unwrap();
    env::set_current_dir(dir).unwrap();
    let all_files_cmd = exec_cmd(
        "find",
        &[
            ".",
            "-type",
            "f",
            "-name",
            match name_filter {
                Some(name) => name,
                None => "*",
            },
        ],
        false,
    )
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
                        if !diff_cmd.status.success() {
                            let diff_stdout = diff_cmd.stdout;
                            let diff = String::from_utf8_lossy(&diff_stdout);
                            warn!("{}", diff);
                        }
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

pub fn check_hashes_check_files(
    dir: &Path,
    hashes: &Value,
    version: &str,
    name_filter: Option<&str>,
) {
    let current_dir = env::current_dir().unwrap();
    env::set_current_dir(dir).unwrap();
    let hashes = hashes.get(version).unwrap();
    for (file, known_hash) in hashes.as_object().unwrap() {
        match name_filter {
            Some(name) => {
                if file.contains(name) {
                    continue;
                }
            }
            None => {}
        }
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
                    let diff_stdout = diff_cmd.stdout;
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

pub fn verify_main_config(config: &PfConfig) {
    let diff_cmd = exec_cmd(
        "diff",
        &[
            "/cf/conf/config.xml",
            &get_fixed_file(
                "/conf.default/config.xml".to_string(),
                match &config.version.as_ref() {
                    Some(version) => version,
                    None => {
                        error!("Version is not available to verify files");
                        return;
                    }
                },
            ),
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let diff_stdout = match diff_cmd.status.success() {
        true => diff_cmd.stdout,
        false => {
            error!("Failed to diff new and old files for config.xml");
            Vec::new()
        }
    };
    let diff = String::from_utf8_lossy(&diff_stdout);
    info!("config.xml diff");
    info!("{}", diff);
}

pub fn get_fixed_file(mut file: String, version: &str) -> String {
    if !["2_2", "2_1", "2_0", "1_2"].contains(&version) {
        file = format!("src/usr/local/www/{}", file.trim_start_matches("./"));
    }
    let git_version = format!("RELENG_{}", version);
    let new_file_name = format!("new_{}", file.split('/').last().unwrap());
    println!("https://raw.githubusercontent.com/pfsense/pfsense/{}/{}",
    git_version, file);
    let file_content = reqwest::blocking::get(&format!(
        "https://raw.githubusercontent.com/pfsense/pfsense/{}/{}",
        git_version, file
    ))
    .unwrap()
    .bytes()
    .unwrap();
    let mut out_file = File::create(&new_file_name).unwrap();
    out_file.write(&file_content).unwrap();
    new_file_name
}

pub fn sshd_protection() {
    let _ = fs::create_dir("./sshd");
    let ssh_dir = Path::new("/etc/ssh");
    let ssh_d_dir = Path::new("/etc/ssh/sshd_config.d");
    match fs::copy(ssh_dir, "/ssh/ssh") {
        Ok(_) => {
            info!("Copied ssh files");
        }
        Err(_) => {
            error!("Failed to copy ssh files");
        }
    }
    let file_content = reqwest::blocking::get(
        "https://raw.githubusercontent.com/jababte19/blueteamrust/mastet/data/sshd_config",
    )
    .unwrap()
    .bytes()
    .unwrap();
    match fs::set_permissions("/etc/ssh/sshd_config", fs::Permissions::from_mode(0o540)) {
        Ok(_) => {}
        Err(_) => {
            error!("Failed to set sshd_config perms to 540");
        }
    }
    let mut out_file = File::create("/etc/ssh/sshd_config").unwrap();
    out_file.write(&file_content).unwrap();
    match fs::set_permissions("/etc/ssh/sshd_config", fs::Permissions::from_mode(0o440)) {
        Ok(_) => {}
        Err(_) => {
            error!("Failed to set sshd_config perms to 440");
        }
    }
    match fs::remove_dir_all(ssh_d_dir) {
        Ok(_) => {}
        Err(_) => {
            error!("Removed to remove sshd_config.d");
        }
    }
    match fs::create_dir(ssh_d_dir) {
        Ok(_) => {}
        Err(_) => {
            error!("Failed to re-create sshd_config.d");
        }
    }
    // if !exec_cmd("service", &["sshd", "start"], false)
    //     .unwrap()
    //     .wait()
    //     .unwrap()
    //     .success()
    // {
    //     error!("Failed to restart ssh");
    // }
    for file in ["authorized_keys", "id_rsa"] {
        let mut count = 1;
        let find_cmd = exec_cmd("/usr/bin/find", &["/", "-name", &file], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        let find_stdout = match find_cmd.status.success() {
            true => find_cmd.stdout,
            false => {
                error!("Failed to find {}", file);
                continue;
            }
        };
        let find_str = String::from_utf8_lossy(&find_stdout).to_string();
        for line in find_str.split("\n") {
            if line.len() == 0 {
                continue;
            }
            if yes_no(format!("Keep file {}", line)) {
                warn!("{} was kept", line);
            } else {
                let file_path = Path::new(line);
                match fs::copy(
                    file_path,
                    &format!(
                        "./sshd/{}{}",
                        file_path.file_name().unwrap().to_str().unwrap(),
                        count
                    ),
                ) {
                    Ok(_) => {}
                    Err(_) => {
                        error!("Failed to copy {}", line);
                    }
                }
                match fs::remove_file(file_path) {
                    Ok(_) => {}
                    Err(_) => {
                        error!("Failed to remove {}", line);
                    }
                }
                info!(
                    "{} was removed and copied to {}",
                    line,
                    format!(
                        "./sshd/{}{}",
                        file_path.file_name().unwrap().to_str().unwrap(),
                        count
                    )
                );
                count += 1;
            }
        }
    }
}

pub fn scan_file_permissions() {
    let find_cmd = exec_cmd("/usr/bin/find", &["/", "-perm", "-4000", "-print"], false)
        .unwrap()
        .wait_with_output()
        .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!("Failed to execute find SUID");
            Vec::new()
        }
    };
    let find_str = String::from_utf8_lossy(&find_stdout).to_string();
    for line in find_str.split("\n") {
        if line.len() == 0 {
            continue;
        }
        warn!("{} has SUID!", line);
    }

    let find_cmd = exec_cmd("/usr/bin/find", &["/", "-perm", "-2000", "-print"], false)
        .unwrap()
        .wait_with_output()
        .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!("Failed to execute find SGID");
            Vec::new()
        }
    };
    let find_str = String::from_utf8_lossy(&find_stdout).to_string();
    for line in find_str.split("\n") {
        if line.len() == 0 {
            continue;
        }
        warn!("{} has SGID!", line);
    }

    let find_cmd = exec_cmd(
        "/usr/bin/find",
        &[
            "/", "-type", "d", r"(", "-perm", "-g+w", "-or", "-perm", "-o+w", r")", "-print",
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!("Failed to execute find world-writable dirs");
            Vec::new()
        }
    };
    let find_str = String::from_utf8_lossy(&find_stdout).to_string();
    for line in find_str.split("\n") {
        if line.len() == 0 {
            continue;
        }
        warn!("{} is world writable!", line);
    }

    let find_cmd = exec_cmd(
        "/usr/bin/find",
        &[
            "/", r"!", "-path", "*/proc/*", r"(", "-perm", "-g+w", "-or", "-perm", "-o+w", r")", "-type", "f", "-print",
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!("Failed to execute find world-writable files");
            Vec::new()
        }
    };
    let find_str = String::from_utf8_lossy(&find_stdout).to_string();
    for line in find_str.split("\n") {
        if line.len() == 0 {
            continue;
        }
        warn!("{} is world writable!", line);
    }
}
