use crate::utils::{exec_cmd, yes_no, PIDInfo};
use std::collections::HashSet;
use std::fmt::Display;

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

    pub fn analyze_pid(&self) -> PIDInfo {
        PIDInfo::new(self.pid.parse().unwrap()).unwrap()
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
    let mut safe: HashSet<Socket> = HashSet::new();
    loop {
        let ss = exec_cmd("sockstat", &[], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        if ss.status.success() {
            for line in String::from_utf8_lossy(&ss.stdout).split("\n") {
                let sock = match Socket::new(line.to_string()) {
                    Ok(sock) => sock,
                    Err(_) => continue,
                };
                let pid = sock.analyze_pid();
                if !safe.contains(&sock) {
                    println!("{}", sock);
                    println!("{}", pid);
                    if yes_no("Keep socket".to_string()) {
                        safe.insert(sock);
                    } else {
                        pid.terminate()
                    }
                }
            }
        }
    }
}
