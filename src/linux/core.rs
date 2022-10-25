use std::fs;
use std::path::Path;
use log::{debug, error, info, warn};
use crate::utils::{
    config::SysConfig,
    tools::{exec_cmd, verify_config},
    user::UserInfo,
};

fn icmp_sysctl_check() {
    let icmp_check = Path::new("/proc/sys/net/ipv4/icmp_echo_ignore_all");
    if fs::read_to_string(icmp_check) == "1" {
        warn!("ICMP Response is Disabled!");
        fs::write(icmp_check, "0");
    }
}

fn sudo_protection() {
    let _ = fs::create_dir("./sudo");
    for g in ["sudo", "wheel"] {
        let getent_cmd = exec_cmd("/usr/bin/getent", &["group", g], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        let getent_stdout = match getent_cmd.status.success() {
            true => getent_cmd.stdout,
            false => {
                error!("Failed to get {} members", g);
                continue;
            }
        };
        let getent_str = String::from_utf8_lossy(&getent_stdout).to_string();
        let sudo_users = getent_str.split(":")[3].split(",");
        for user in sudo_users {
            if yes_no(format!("Remove {} from {}", user, g)) {
                if !exec_cmd("/usr/bin/gpasswd", &["-d", &user, &g], false)
                    .unwrap()
                    .wait()
                    .unwrap()
                    .success()
                {
                    error!("Failed to start {}", service);
                    continue;
                }
            } else {
                warn!("{} has {} power", user, g);
            }
        }
    }
    let sudoers_path = Path::new("/etc/sudoers");
    let sudoers_d_path = Path::new("/etc/sudoers.d");
    fs::copy(sudoers_path,"/sudo/sudoers");
    fs::copy(sudoers_d_path,"/sudo/sudoers.d");
    let sudo_group = yes_no("Yes for Sudo, No for Wheel");
    let file_content = match sudo_group {
        true => reqwest::blocking::get("https://raw.githubusercontent.com/jababte19/blueteamrust/mastet/data/sudoers_sudo"),
        false => reqwest::blocking::get("https://raw.githubusercontent.com/jababte19/blueteamrust/mastet/data/sudoers_wheel")
    }
    .unwrap()
    .bytes()
    .unwrap();
    fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o540));
    let mut out_file = File::open();
    out_file.write(&file_content).unwrap();
    fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o440));
    fs::remove_dir_all(sudoers_d_path);
    fs::create_dir(sudoers_d_path);
}

fn sshd_protection() {
    let _ = fs::create_dir("./sshd");
    let ssh_dir = Path::new("/etc/ssh");
    let ssh_d_dir = Path::new("/etc/ssh/sshd_config.d");
    fs::copy(ssh_dir,"/ssh/ssh");
    let file_content = reqwest::blocking::get("https://raw.githubusercontent.com/jababte19/blueteamrust/mastet/data/sshd_config")
    .unwrap()
    .bytes()
    .unwrap();
    fs::set_permissions(ssh_dir, fs::Permissions::from_mode(0o540));
    let mut out_file = File::open();
    out_file.write(&file_content).unwrap();
    fs::set_permissions(ssh_dir, fs::Permissions::from_mode(0o440));
    fs::remove_dir_all(ssh_d_dir);
    fs::create_dir(ssh_d_dir);
    if !exec_cmd("/usr/bin/systemctl", &["start", "sshd"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        if !exec_cmd("/usr/bin/systemctl", &["start", "ssh"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to restart ssh");
        }
    }
    for file in ["authorized_keys", "id_rsa"] {
        let count = 1;
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
            if len(line) == 0 {
                continue;
            }
            if yes_no(format!("Keep file {}", line)) {
                warn!("{} was kept", line);
            } else {
                let file_path = Path::new(line);
                fs::copy(file_path, &format!("./sshd/{}{}", file_path.file_name(), count));
                fs::remove_file(file_path);
                info!("{} was removed and copied to {}", line, format!("./sshd/{}{}", file_path.file_name(), count));
                count++;
            }
        }
    }
    
}

fn scan_file_permissions() {
    let find_cmd = exec_cmd("/usr/bin/find", &["/", "-perm", "-4000", "-print"], false)
    .unwrap()
    .wait_with_output()
    .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!("Failed to execute find SUID");
            continue;
        }
    };
    let find_str = String::from_utf8_lossy(&find_stdout).to_string();
    for line in find_str.split("\n") {
        if len(line) == 0 {
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
            continue;
        }
    };
    let find_str = String::from_utf8_lossy(&find_stdout).to_string();
    for line in find_str.split("\n") {
        if len(line) == 0 {
            continue;
        }
        warn!("{} has SGID!", line);
    }

    let find_cmd = exec_cmd("/usr/bin/find", &["/", "-type", "d", "\(", "-perm", "-g+w", "-or" ,"-perm", "-o+w", "\)", "-print"], false)
    .unwrap()
    .wait_with_output()
    .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!("Failed to execute find world-writable dirs");
            continue;
        }
    };
    let find_str = String::from_utf8_lossy(&find_stdout).to_string();
    for line in find_str.split("\n") {
        if len(line) == 0 {
            continue;
        }
        warn!("{} is world writable!", line);
    }

    let find_cmd = exec_cmd("/usr/bin/find", &["/", "-!", "-path", "*/proc/*", "-perm", "-2", "-type", "f", "-print"], false)
    .unwrap()
    .wait_with_output()
    .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!("Failed to execute find world-writable files");
            continue;
        }
    };
    let find_str = String::from_utf8_lossy(&find_stdout).to_string();
    for line in find_str.split("\n") {
        if len(line) == 0 {
            continue;
        }
        warn!("{} is world writable!", line);
    }
}