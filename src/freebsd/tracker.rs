use crate::utils::{
    pid::PIDInfo,
    tools::{exec_cmd, yes_no},
};
use log::{error, info, warn};
use std::collections::HashSet;
use std::fmt::Display;
use std::fs::create_dir;

#[derive(Eq, Hash, PartialEq)]
struct Socket {
    user: String,
    command: String,
    pid: String,
    fd: String,
    proto: String,
    local: String,
    foreign: String,
}

impl Socket {
    pub fn new(line: String) -> Result<Socket, Box<dyn std::error::Error>> {
        let mut comps = line.split_whitespace();
        let user = comps.next().ok_or("Error parsing line")?.to_owned();
        let command = comps.next().ok_or("Error parsing line")?.to_owned();
        let pid = comps.next().ok_or("Error parsing line")?.to_owned();
        let fd = comps.next().ok_or("Error parsing line")?.to_owned();
        let proto = comps.next().ok_or("Error parsing line")?.to_owned();
        let local = comps.next().ok_or("Error parsing line")?.to_owned();
        let foreign = comps.next().ok_or("Error parsing line")?.to_owned();
        Ok(Socket {
            user,
            command,
            pid,
            fd,
            proto,
            local,
            foreign,
        })
    }

    pub fn analyze_pid(&self) -> Option<PIDInfo> {
        match &self.pid.parse::<u64>() {
            Ok(pid) => PIDInfo::new(*pid),
            Err(_) => None,
        }
    }
}

impl Display for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{} | {} | {} | {} | {} | {} | {}",
            self.user, self.command, self.pid, self.fd, self.proto, self.local, self.foreign
        )
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = create_dir("./quarantine");
    let mut safe: HashSet<Socket> = HashSet::new();
    loop {
        let ss = exec_cmd("/usr/bin/sockstat", &[], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        if ss.status.success() {
            let ss_stdout = ss.stdout;
            let line_str = String::from_utf8_lossy(&ss_stdout);
            let mut lines = line_str.split("\n");
            let _ = lines.next();
            for line in lines {
                let sock = match Socket::new(line.to_string()) {
                    Ok(sock) => sock,
                    Err(_) => continue,
                };
                let pid = sock.analyze_pid();
                if !safe.contains(&sock) {
                    println!("{}", sock);
                    match pid {
                        Some(p) => {
                            println!("{}", p);
                            if yes_no("Keep socket".to_string()) {
                                info!("{} kept", sock);
                                safe.insert(sock);
                            } else {
                                p.terminate();
                                warn!("{} was found to be malicious!", sock);
                                warn!("PID: {}", p);
                                if yes_no("Do you want to quarantine the binary".to_owned()) {
                                    p.quarantine();
                                    info!("{} quarantined", p.exe);
                                }
                            }
                        },
                        None => {
                            println!("PID Info Unavailable")
                        }
                    }
                }
            }
        } else {
            error!("Failed to get Socket data");
        }
    }
}
