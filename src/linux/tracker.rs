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
    net_id: String,
    state: String,
    recv_q: String,
    send_q: String,
    local_addr: String,
    peer_addr: String,
    process: String,
}

impl Socket {
    pub fn new(line: String) -> Result<Socket, Box<dyn std::error::Error>> {
        let mut comps = line.split_whitespace();
        let net_id = comps.next().ok_or("Error parsing line")?.to_owned();
        let state = comps.next().ok_or("Error parsing line")?.to_owned();
        let recv_q = comps.next().ok_or("Error parsing line")?.to_owned();
        let send_q = comps.next().ok_or("Error parsing line")?.to_owned();
        let local = comps.next().ok_or("Error parsing line")?.to_owned();
        let peer = comps.next().ok_or("Error parsing line")?.to_owned();
        let process = match comps.next() {
            Some(proc) => proc,
            None => "N/A",
        }
        .to_owned();
        Ok(Socket {
            net_id,
            state,
            recv_q,
            send_q,
            local_addr: local,
            peer_addr: peer,
            process,
        })
    }

    pub fn analyze_pid(&self) -> Vec<PIDInfo> {
        let mut out: Vec<PIDInfo> = Vec::new();
        let proc_data = String::from(&self.process);
        let pid_locs: Vec<usize> = proc_data.match_indices("pid=").map(|(i, _)| i).collect();
        for pid_loc in pid_locs {
            let mut iter = proc_data.chars();
            for _ in 0..pid_loc + 4 {
                iter.next();
            }
            let mut pid_end = pid_loc + 4;
            loop {
                match iter.next() {
                    Some(c) => {
                        if !c.is_ascii_digit() {
                            break;
                        }
                    }
                    None => {
                        return out;
                    }
                }
                pid_end += 1;
            }
            out.push(PIDInfo::new(proc_data[pid_loc + 4..pid_end].parse().unwrap()).unwrap());
        }
        out
    }
}

impl Display for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{} | {} | {} | {} | {} | {} | {}",
            self.net_id,
            self.state,
            self.recv_q,
            self.send_q,
            self.local_addr,
            self.peer_addr,
            self.process
        )
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = create_dir("./quarantine");
    let mut safe: HashSet<Socket> = HashSet::new();
    loop {
        let ss = exec_cmd("/usr/bin/ss", &["-tupn0"], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        if ss.status.success() {
            let out = String::from_utf8_lossy(&ss.stdout);
            // debug!("{}", out);
            let splits: Vec<&str> = out.split("\n").collect();
            for line in &splits[1..] {
                if line.len() == 0 {
                    continue;
                }
                let sock = match Socket::new(line.to_string()) {
                    Ok(sock) => sock,
                    Err(e) => {
                        error!("Error making socket: {}", e);
                        continue;
                    }
                };
                let pids = sock.analyze_pid();
                if !safe.contains(&sock) {
                    println!("{}", sock);
                    for pid in &pids {
                        println!("{}", pid);
                    }
                    if yes_no("Keep socket".to_string()) {
                        info!("{} kept", sock);
                        safe.insert(sock);
                    } else {
                        warn!("{} was found to be malicious!", sock);
                        for pid in &pids {
                            warn!("{}", pid);
                            if yes_no("Do you want to quarantine/terminate the binary".to_owned()) {
                                pid.quarantine();
                                pid.terminate();
                                info!("{} quarantined/terminated", pid.exe);
                            }
                        }
                    }
                }
            }
        } else {
            error!("Failed to grab socket data");
        }
    }
}
