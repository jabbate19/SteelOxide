use crate::utils::PIDInfo;

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

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("This is not yet implemented!");
    Ok(())
}
