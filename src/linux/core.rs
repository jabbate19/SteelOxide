use crate::utils::tools::{exec_cmd, yes_no};
use log::{error, info, warn};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn icmp_sysctl_check() {
    let icmp_check = Path::new("/proc/sys/net/ipv4/icmp_echo_ignore_all");
    if fs::read_to_string(icmp_check).unwrap() == "1" {
        warn!("ICMP Response is Disabled!");
        match fs::write(icmp_check, "0") {
            Ok(_) => {
                info!("Reset ICMP sys var");
            }
            Err(_) => {
                error!("Failed to write to /proc/sys/net/ipv4/icmp_echo_ignore_all");
            }
        }
    }
}

pub fn sudo_protection() {
    let sudoers_path = Path::new("/etc/sudoers");
    let sudoers_d_path = Path::new("/etc/sudoers.d");
    match fs::copy(sudoers_path, "./sudo/sudoers") {
        Ok(_) => {
            info!("Copied /etc/sudoers");
        }
        Err(_) => {
            error!("Failed to copy /etc/sudoers");
        }
    }
    match fs::copy(sudoers_d_path, "./sudo/sudoers.d") {
        Ok(_) => {
            info!("Copied /etc/sudoers.d");
        }
        Err(_) => {
            error!("Failed to copy /etc/sudoers.d");
        }
    }
    let sudo_group = yes_no("Yes for Sudo, No for Wheel".to_string());
    let _ = fs::create_dir("./sudo");
    let mut g = "wheel";
    if sudo_group {
        g = "sudo";
    }
    let getent_cmd = exec_cmd("/usr/bin/getent", &["group", g], false)
        .unwrap()
        .wait_with_output()
        .unwrap();
    let getent_stdout = match getent_cmd.status.success() {
        true => getent_cmd.stdout,
        false => {
            error!("Failed to get {} members", g);
            Vec::new()
        }
    };
    let getent_str = String::from_utf8_lossy(&getent_stdout).to_string();
    let sudo_users = getent_str.trim().split(":").last().unwrap().split(",");
    for user in sudo_users {
        if user.len() == 0 {
            continue;
        }
        if yes_no(format!("Remove {} from {}", &user, g)) {
            if !exec_cmd("/usr/bin/gpasswd", &["-d", &user, &g], false)
                .unwrap()
                .wait()
                .unwrap()
                .success()
            {
                error!("Failed to remove {} from {}", g, &user);
                continue;
            }
        } else {
            warn!("{} has {} power", &user, g);
        }
    }
    open_firewall();
    let file_content = match sudo_group {
        true => reqwest::blocking::get(
            "https://raw.githubusercontent.com/jabbate19/blueteamrust/master/data/sudoers_sudo",
        ),
        false => reqwest::blocking::get(
            "https://raw.githubusercontent.com/jabbate19/blueteamrust/master/data/sudoers_wheel",
        ),
    }
    .unwrap()
    .bytes()
    .unwrap();
    close_firewall();
    match fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o540)) {
        Ok(_) => {}
        Err(_) => {
            error!("Failed to chmod /etc/sudoers to 540");
        }
    }
    let mut out_file = File::create(sudoers_path).unwrap();
    out_file.write(&file_content).unwrap();
    match fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o440)) {
        Ok(_) => {}
        Err(_) => {
            error!("Failed to chmod /etc/sudoers to 440");
        }
    }
    match fs::remove_dir_all(sudoers_d_path) {
        Ok(_) => {
            info!("Cleared /etc/sudoers.d");
        }
        Err(_) => {
            error!("Failed to remove /etc/sudoers.d");
        }
    }
    match fs::create_dir(sudoers_d_path) {
        Ok(_) => {}
        Err(_) => {
            error!("Failed to re-create /etc/sudoers.d");
        }
    }
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
    open_firewall();
    let file_content = reqwest::blocking::get(
        "https://raw.githubusercontent.com/jabbate19/blueteamrust/master/data/sshd_config",
    )
    .unwrap()
    .bytes()
    .unwrap();
    close_firewall();
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
    let find_stdout = find_cmd.stdout;
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
    let find_stdout = find_cmd.stdout;
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
            "/", "-type", "d", "(", "-perm", "-g+w", "-or", "-perm", "-o+w", ")", "-print",
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!(
                "Failed to execute find world-writable dirs: {}",
                String::from_utf8_lossy(&find_cmd.stderr)
            );
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
            "/", "-!", "-path", "*/proc/*", "-perm", "-2", "-type", "f", "-print",
        ],
        false,
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    let find_stdout = match find_cmd.status.success() {
        true => find_cmd.stdout,
        false => {
            error!(
                "Failed to execute find world-writable files: {}",
                String::from_utf8_lossy(&find_cmd.stderr)
            );
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

pub fn open_firewall() {
    if !exec_cmd("/usr/sbin/iptables", &["-P", "INPUT", "ACCEPT"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to open INPUT");
    }

    if !exec_cmd("/usr/sbin/iptables", &["-P", "OUTPUT", "ACCEPT"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to open OUTPUT");
    }
}

pub fn close_firewall() {
    if !exec_cmd("/usr/sbin/iptables", &["-P", "INPUT", "DROP"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to close INPUT");
    }

    if !exec_cmd("/usr/sbin/iptables", &["-P", "OUTPUT", "DROP"], false)
        .unwrap()
        .wait()
        .unwrap()
        .success()
    {
        error!("Failed to close OUTPUT");
    }
}
