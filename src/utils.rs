use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use std::{
    fmt::Display,
    fs::{read_link, read_to_string, File},
    io::{self, stdin, stdout, BufRead, Write},
    net::IpAddr,
    path::Path,
    process::Child,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SysConfig {
    pub ip: IpAddr,
    pub interface: String,
    pub ports: Vec<String>,
    pub services: Vec<String>,
    pub users: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Permissions {
    pub ip: String,
    pub ports: Vec<String>,
    pub allow_icmp: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PfConfig {
    pub lan_ip: IpAddr,
    pub lan_subnet: String,
    pub lan_interface: String,
    pub wan_ip: IpAddr,
    pub wan_subnet: String,
    pub wan_interface: String,
    pub permissions: Vec<Permissions>,
    pub users: Vec<String>,
}

pub struct UserInfo {
    pub username: String,
    pub password: String,
    pub uid: u32,
    pub gid: u32,
    pub userinfo: String,
    pub homedir: String,
    pub shell: String,
}

impl UserInfo {
    pub fn new(line: String) -> Result<UserInfo, Box<dyn std::error::Error>> {
        let comps: Vec<&str> = line.split(":").collect();
        Ok(UserInfo {
            username: comps[0].to_owned(),
            password: comps[1].to_owned(),
            uid: comps[2].parse()?,
            gid: comps[3].parse()?,
            userinfo: comps[4].to_owned(),
            homedir: comps[5].to_owned(),
            shell: comps[6].to_owned(),
        })
    }

    pub fn get_all_users() -> Vec<UserInfo> {
        let mut out: Vec<UserInfo> = Vec::new();
        if let Ok(lines) = read_lines("/etc/passwd") {
            // Consumes the iterator, returns an (Optional) String
            for line in lines {
                if let Ok(entry) = line {
                    if let Ok(user) = UserInfo::new(entry) {
                        out.push(user);
                    }
                }
            }
        }
        out
    }

    #[cfg(target_os = "linux")]
    pub fn shutdown(&self) {
        let _ = exec_cmd("usermod", &["-L", &self.username], false)
            .unwrap()
            .wait();
        let _ = exec_cmd("usermod", &["-s", "/bin/false", &self.username], false)
            .unwrap()
            .wait();
        let _ = exec_cmd("gpasswd", &["--delete", &self.username, "sudo"], false)
            .unwrap()
            .wait();
    }

    #[cfg(target_os = "freebsd")]
    pub fn shutdown(&self) {
        let _ = exec_cmd("pw", &["lock", &self.username], false)
            .unwrap()
            .wait();
        let _ = exec_cmd(
            "pw",
            &["usermod", "-s", "/bin/false", &self.username],
            false,
        )
        .unwrap()
        .wait();
        let _ = exec_cmd("pw", &["wheel", "-d", &self.username], false)
            .unwrap()
            .wait();
    }
}

pub struct PIDInfo {
    pub pid: u64,
    pub exe: String,
    pub root: String,
    pub cwd: String,
    pub cmdline: String,
    pub environ: String,
}

impl PIDInfo {
    #[cfg(target_os = "linux")]
    pub fn new(pid: u64) -> Result<PIDInfo, Box<dyn std::error::Error>> {
        let exe = read_link(format!("/proc/{}/exe", pid))?
            .display()
            .to_string();
        let root = read_link(format!("/proc/{}/root", pid))?
            .display()
            .to_string();
        let cwd = read_link(format!("/proc/{}/cwd", pid))?
            .display()
            .to_string();
        let cmdline = read_to_string(format!("/proc/{}/cmdline", pid))?;
        let environ = read_to_string(format!("/proc/{}/environ", pid))?;
        Ok(PIDInfo {
            pid,
            exe,
            root,
            cwd,
            cmdline,
            environ,
        })
    }

    #[cfg(target_os = "freebsd")]
    pub fn new(pid: u64) -> Result<PIDInfo, Box<dyn std::error::Error>> {
        let exe_stdout = exec_cmd("procstat", &["-b", &pid.to_string()[..]], false)
            .unwrap()
            .wait_with_output()
            .unwrap()
            .stdout;
        let exe_full = String::from_utf8_lossy(&exe_stdout);
        let exe = exe_full.split_whitespace().last().unwrap();

        let cwd_stdout = exec_cmd("procstat", &["pwdx", &pid.to_string()[..]], false)
            .unwrap()
            .wait_with_output()
            .unwrap()
            .stdout;
        let cwd_full = String::from_utf8_lossy(&cwd_stdout);
        let cwd = cwd_full.split_whitespace().last().unwrap();

        let cmdline_stdout = exec_cmd("procstat", &["pargs", &pid.to_string()[..]], false)
            .unwrap()
            .wait_with_output()
            .unwrap()
            .stdout;
        let cmdline_full = String::from_utf8_lossy(&cmdline_stdout);
        let mut cmdline: Vec<String> = Vec::new();
        for line in cmdline_full.split('\n') {
            cmdline.push(line.split_once(':').unwrap().1.trim().to_owned());
        }
        cmdline.remove(0);

        let environ_stdout = exec_cmd("procstat", &["penv", &pid.to_string()[..]], false)
            .unwrap()
            .wait_with_output()
            .unwrap()
            .stdout;
        let environ_full = String::from_utf8_lossy(&environ_stdout);
        let mut environ: Vec<String> = Vec::new();
        for line in environ_full.split('\n') {
            environ.push(line.split_once(':').unwrap().1.trim().to_owned());
        }
        environ.remove(0);

        Ok(PIDInfo {
            pid,
            exe: exe.to_string(), // -b
            root: String::from("N/A"),
            cwd: cwd.to_string(),              // pwdx
            cmdline: format!("{:?}", cmdline), // pargs
            environ: format!("{:?}", environ), // penv
        })
    }

    pub fn terminate(&self) {
        let _ = exec_cmd("kill", &["-9", &self.pid.to_string()], false)
            .unwrap()
            .wait();
    }
}

impl Display for PIDInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} | {} | {} | {} | {}",
            self.pid, self.exe, self.root, self.cwd, self.cmdline
        )
    }
}

pub fn exec_cmd(cmd: &str, args: &[&str], stdin_req: bool) -> Result<Child, io::Error> {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(match stdin_req {
            true => Stdio::piped(),
            false => Stdio::null(),
        })
        .spawn()
}

pub fn yes_no(question: String) -> bool {
    loop {
        print!("{} (y/n)? ", question);
        let _ = stdout().flush();
        let mut input = String::new();
        stdin().read_line(&mut input).unwrap();
        match input.to_lowercase().chars().nth(0) {
            Some('y') => {
                return true;
            }
            Some('n') => {
                return false;
            }
            _ => continue,
        }
    }
}

pub fn verify_config(config: SysConfig) -> bool {
    println!("{:?}", config);
    yes_no("Config Ok".to_owned())
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
