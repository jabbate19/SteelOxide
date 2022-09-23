use std::collections::HashSet;
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use crate::utils::{exec_cmd, PIDInfo, yes_no};


#[derive(Eq, Hash, PartialEq)]
struct Socket {
    net_id: String,
    state: String,
    recv_q: String,
    send_q: String,
    local_addr: IpAddr,
    local_port: u16,
    peer_addr: IpAddr,
    peer_port: u16,
    process: String,
}

impl Socket {
    pub fn new(line: String) -> Result<Socket, Box<dyn std::error::Error>> {
        let mut comps = line.split_whitespace();
        let net_id = comps.next().ok_or("Error parsing line")?.to_owned();
        let state = comps.next().ok_or("Error parsing line")?.to_owned();
        let recv_q = comps.next().ok_or("Error parsing line")?.to_owned();
        let send_q = comps.next().ok_or("Error parsing line")?.to_owned();
        let local: SocketAddr = comps.next().ok_or("Error parsing line")?.parse()?;
        let peer: SocketAddr = comps.next().ok_or("Error parsing line")?.parse()?;
        let process = comps.next().ok_or("Error parsing line")?.to_owned();
        Ok(Socket {
            net_id,
            state,
            recv_q,
            send_q,
            local_addr: local.ip(),
            local_port: local.port(),
            peer_addr: peer.ip(),
            peer_port: peer.port(),
            process,
        })
    }

    pub fn analyze_pid(&self) -> Vec<PIDInfo> {
        let mut out: Vec<PIDInfo> = Vec::new();
        let index: u64 = 0;
        let proc_data = String::from(&self.process);
        let pid_locs: Vec<usize> = proc_data.match_indices("pid=").map(|(i, _)|i).collect();
        for pid_loc in pid_locs {
            let mut iter = proc_data.chars();
            for _ in 0..pid_loc+4 {
                iter.next();
            }
            let mut pid_end = pid_loc+4;
            loop {
                match iter.next() {
                    Some(c) => {
                        if !c.is_ascii_digit() {
                            break;
                        }
                    },
                    None => {
                        return out;
                    },
                }
                pid_end += 1;
            }
            out.push(PIDInfo::new(proc_data[pid_loc+4..pid_end].parse().unwrap()).unwrap());
        }
        out
    }
}

impl Display for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{} | {} | {} | {} | {}:{} | {}:{} | {}", self.net_id, self.state, self.recv_q, self.send_q, self.local_addr, self.local_port, self.peer_addr, self.peer_port, self.process)
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut safe: HashSet<Socket> = HashSet::new();
    loop {
        let ss = exec_cmd("ss",&["-tupn0"], false).unwrap().wait_with_output().unwrap();
        if ss.status.success() {
            for line in String::from_utf8_lossy(&ss.stdout).split("\n") {
                let sock = match Socket::new(line.to_string()) {
                    Ok(sock) => sock,
                    Err(_) => continue,
                };
                let pids = sock.analyze_pid();
                if !safe.contains(&sock) {
                    println!("{}", sock);
                    if yes_no("Keep socket".to_string()) {
                        safe.insert(sock);
                    } else {
                        for pid in pids {
                            pid.terminate()
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
