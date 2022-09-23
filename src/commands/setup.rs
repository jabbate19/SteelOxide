use std::{io::Write, process::ExitStatus};

use crate::utils::exec_cmd;

fn change_password(user: &str, password: &str) -> ExitStatus {
    let mut proc = exec_cmd("passwd", &[user], true).unwrap();
    proc.stdin
        .as_ref()
        .unwrap()
        .write_all(password.as_bytes())
        .unwrap();
    proc.stdin
        .as_ref()
        .unwrap()
        .write_all(password.as_bytes())
        .unwrap();
    proc.wait().unwrap()
}

fn configure_firewall() {}

fn audit_users() {}

fn select_services() {}

fn sudo_protection() {}

fn sshd_protection() {}

fn scan_file_permissions() {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
