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
        todo!()
    }
}

impl Display for Socket {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        todo!()
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut safe: HashSet<Socket> = HashSet::new();
    loop {
        let ss = exec_cmd("ss",&["-tupn0"], false).unwrap().wait_with_output().unwrap();
        if ss.status.success() {
            for line in String::from_utf8_lossy(&ss.stdout).split("\n") {
                let sock = Socket::new(line.to_string())?;
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
