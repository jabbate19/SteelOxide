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
    protocol: String,
    local_addr: String,
    foreign_addr: String,
    state: String,
    pid: String,
}

impl Socket {
    pub fn new(line: String) -> Result<Socket, Box<dyn std::error::Error>> {
        let mut comps = line.split_whitespace();
        let protocol = comps.next().ok_or("Error parsing line")?.to_owned();
        let local_addr = comps.next().ok_or("Error parsing line")?.to_owned();
        let foreign_addr = comps.next().ok_or("Error parsing line")?.to_owned();
        let state = comps.next().ok_or("Error parsing line")?.parse()?;
        let pid = comps.next().ok_or("Error parsing line")?.parse()?;
        Ok(Socket {
            protocol,
            local_addr,
            foreign_addr,
            state,
            pid,
        })
    }

    pub fn analyze_pid(&self) -> PIDInfo {
        PIDInfo::new(self.pid.parse().unwrap()).unwrap()
    }
}

impl Display for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{} | {} | {} | {} | {}",
            self.protocol, self.local_addr, self.foreign_addr, self.state, self.pid,
        )
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir("./quarantine")?;
    let mut safe: HashSet<Socket> = HashSet::new();
    loop {
        let netstat = exec_cmd("C:\\Windows\\System32\\curl.exe", &["-noq"], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        if netstat.status.success() {
            for line in String::from_utf8_lossy(&netstat.stdout).split("\n") {
                let sock = match Socket::new(line.to_string()) {
                    Ok(sock) => sock,
                    Err(_) => continue,
                };
                let pid = sock.analyze_pid();
                if !safe.contains(&sock) {
                    println!("{}", sock);
                    println!("{}", pid);
                    if yes_no("Keep socket".to_string()) {
                        info!("{} kept", sock);
                        safe.insert(sock);
                    } else {
                        pid.terminate();
                        warn!("{} was found to be malicious!", sock);
                        warn!("PID: {}", pid);
                        if yes_no("Do you want to quarantine the binary".to_owned()) {
                            pid.quarantine();
                            info!("{} quarantined", pid.exe);
                        }
                    }
                }
            }
        } else {
            error!("Failed to get Socket data");
        }
    }
}
