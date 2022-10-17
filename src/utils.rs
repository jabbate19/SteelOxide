use get_if_addrs::{get_if_addrs, Interface};
use serde::{Deserialize, Serialize};
use std::process::{Command, ExitStatus, Stdio};
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
    pub dmz_ip: Option<IpAddr>,
    pub dmz_subnet: Option<String>,
    pub dmz_interface: Option<String>,
    pub version: Option<String>,
    pub permissions: Vec<Permissions>,
    pub users: Vec<String>,
}

#[derive(Debug)]
pub struct ADUserInfo {
    pub name: String,
    pub display_name: String,
    pub sam_account_name: String,
    pub enabled: bool,
    pub groups: Vec<String>,
}

impl ADUserInfo {
    pub fn new(line: String) -> Option<ADUserInfo> {
        let mut out = ADUserInfo {
            name: "N/A".to_owned(),
            display_name: "N/A".to_owned(),
            sam_account_name: "N/A".to_owned(),
            enabled: false,
            groups: Vec::new(),
        };
        let mut something = false;
        let comps: Vec<&str> = line.split("\r\n").collect();
        for comp in comps {
            match comp.split_once(':') {
                Some(key_val) => {
                    let key = key_val.0.trim();
                    let val = key_val.1.trim().to_owned();
                    match key {
                        "Name" => {
                            out.name = val;
                            something = true;
                        }
                        "DisplayName" => {
                            out.display_name = val;
                            something = true;
                        }
                        "SamAccountname" => {
                            out.sam_account_name = val;
                            something = true;
                        }
                        "Enabled" => {
                            out.enabled = val == "True";
                            something = true;
                        }
                        "Groups" => {
                            let groups_str = val.split(',');
                            let mut groups: Vec<String> = Vec::new();
                            for group in groups_str {
                                groups.push(group.to_owned());
                            }
                            something = true;
                        }
                        _ => {}
                    }
                }
                None => {}
            }
        }
        if something {
            Some(out)
        } else {
            None
        }
    }

    pub fn get_all_users() -> Vec<ADUserInfo> {
        let mut out: Vec<ADUserInfo> = Vec::new();
        let all_users_cmd = exec_cmd("powershell", &[
            "-ExecutionPolicy",
            "Bypass",
            "Get-ADUser -Filter * -Properties SamAccountname,Name,DisplayName,Enabled,memberof | % {New-Object PSObject -Property @{Name = $_.Name; DisplayName = $_.DisplayName; SamAccountname= $_.SamAccountname; Enabled = $_.Enabled; Groups = ($_.memberof | Get-ADGroup | Select -ExpandProperty Name) -join \",\"}} | Select Name, DisplayName, Enabled, SamAccountname, Groups | Format-List"
        ], false).unwrap().wait_with_output().unwrap();
        let all_users_str = String::from_utf8_lossy(&all_users_cmd.stdout);
        let all_users_split = all_users_str.split("\r\n\r\n");
        for user in all_users_split {
            match ADUserInfo::new(user.to_owned()) {
                Some(ad_user) => {
                    out.push(ad_user);
                }
                None => {}
            }
        }
        out
    }

    pub fn shutdown(&self) {
        let _ = exec_cmd("net", &["user", "/domain", &self.name, "/active:no"], false)
            .unwrap()
            .wait();
    }

    pub fn change_password(&self, password: &str) -> ExitStatus {
        let mut proc = exec_cmd("net", &["user", "/domain", &self.name, password], false).unwrap();
        proc.wait().unwrap()
    }
}

#[derive(Debug)]
pub struct LocalUserInfo {
    pub name: String,
    pub full_name: String,
    pub enabled: bool,
    pub groups: Vec<String>,
}

impl LocalUserInfo {
    pub fn new(name: String) -> Option<LocalUserInfo> {
        let mut out = LocalUserInfo {
            name: "N/A".to_owned(),
            full_name: "N/A".to_owned(),
            enabled: false,
            groups: Vec::new(),
        };
        let fields_out = exec_cmd("net", &["user", &name], false)
            .unwrap()
            .wait_with_output()
            .unwrap()
            .stdout;
        let fields_str = String::from_utf8_lossy(&fields_out);
        let fields_split = fields_str.split("\r\n");
        let mut something = false;
        for field in fields_split {
            let (k, v) = match field.split_once("  ") {
                Some(key_val) => key_val,
                None => {
                    continue;
                }
            };
            let key = k.to_owned().trim().to_owned();
            let val = v.to_owned().trim().to_owned();
            let trimmed = key.trim();
            match trimmed {
                "User name" => {
                    out.name = val;
                    something = true;
                }
                "Full Name" => {
                    out.full_name = val;
                    something = true;
                }
                "Account active" => {
                    out.enabled = val == "Yes";
                    something = true;
                }
                "Local Group Memberships" => {
                    let group_strings = val.split('*');
                    for group in group_strings {
                        let group_trimmed = group.trim().to_owned();
                        if group_trimmed.len() != 0 {
                            out.groups.push(group_trimmed);
                        }
                    }
                    something = true;
                }
                "Global Group Memberships" => {
                    let group_strings = val.split('*');
                    for group in group_strings {
                        let group_trimmed = group.trim().to_owned();
                        if group_trimmed.len() != 0 {
                            out.groups.push(group_trimmed);
                        }
                    }
                    something = true;
                }
                _ => {}
            }
        }
        if something {
            Some(out)
        } else {
            None
        }
    }

    pub fn get_all_users() -> Vec<LocalUserInfo> {
        let mut out: Vec<LocalUserInfo> = Vec::new();
        let all_users_out = exec_cmd(
            "powershell",
            &[
                "-ExecutionPolicy",
                "Bypass",
                "Get-LocalUser | Select-Object Name",
            ],
            false,
        )
        .unwrap()
        .wait_with_output()
        .unwrap()
        .stdout;
        let all_users_str = String::from_utf8_lossy(&all_users_out);
        let all_users_split = all_users_str.split("\r\n");
        for user in all_users_split {
            match LocalUserInfo::new(user.trim().to_owned()) {
                Some(local_user) => {
                    out.push(local_user);
                }
                None => {}
            }
        }
        out
    }

    pub fn change_password(&self, password: &str) -> ExitStatus {
        let mut proc = exec_cmd("net", &["user", &self.name, password], false).unwrap();
        proc.wait().unwrap()
    }

    pub fn shutdown(&self) {
        let _ = exec_cmd("net", &["user", &self.name, "/active:no"], false)
            .unwrap()
            .wait();
    }
}

#[derive(Debug)]
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

    pub fn change_password(&self, password: &str) -> ExitStatus {
        let mut proc = exec_cmd("passwd", &[&self.username], true).unwrap();
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
}

pub struct PIDInfo {
    pub pid: u64,
    pub exe: String,
    pub root: String,
    pub cwd: String,
    pub cmdline: String,
    pub environ: String,
}

#[cfg(target_os = "linux")]
impl PIDInfo {
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

    pub fn terminate(&self) {
        let _ = exec_cmd("kill", &["-9", &self.pid.to_string()], false)
            .unwrap()
            .wait();
    }

    pub fn quarantine(&self) {
        let _ = exec_cmd("mv", &[&self.exe, "./quarantine"], false)
            .unwrap()
            .wait();
        let _ = exec_cmd("chmod", &["444", &self.exe], false)
            .unwrap()
            .wait();
    }
}

#[cfg(target_os = "freebsd")]
impl PIDInfo {
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

    pub fn quarantine(&self) {
        let _ = exec_cmd("mv", &[&self.exe, "./quarantine"], false)
            .unwrap()
            .wait();
        let _ = exec_cmd("chmod", &["444", &self.exe], false)
            .unwrap()
            .wait();
    }
}

#[cfg(target_os = "windows")]
impl PIDInfo {
    pub fn new(pid: u64) -> Result<PIDInfo, Box<dyn std::error::Error>> {
        let mut out = PIDInfo {
            pid,
            exe: String::from("N/A"),
            root: String::from("N/A"),
            cwd: String::from("N/A"),
            cmdline: String::from("N/A"),
            environ: String::from("N/A"),
        };
        let exe_stdout = exec_cmd("powershell", &["-ExecutionPolicy", "Bypass", &format!("Get-WmiObject Win32_Process -Filter \"ProcessId = {}\" | Select-Object ExecutablePath, CommandLine | Format-List", pid)], false)
            .unwrap()
            .wait_with_output()
            .unwrap()
            .stdout;
        let exe = String::from_utf8_lossy(&exe_stdout);

        let comps: Vec<&str> = exe.split("\r\n").collect();
        for comp in comps {
            match comp.split_once(':') {
                Some(key_val) => {
                    let key = key_val.0.trim();
                    let val = key_val.1.trim().to_owned();
                    match key {
                        "ExecutablePath" => {
                            out.exe = val;
                        }
                        "CommandLine" => {
                            out.cmdline = val;
                        }
                        _ => {}
                    }
                }
                None => {}
            }
        }
        Ok(out)
    }

    pub fn terminate(&self) {
        let _ = exec_cmd("taskkill", &["/PID", &self.pid.to_string(), "/F"], false)
            .unwrap()
            .wait();
    }

    pub fn quarantine(&self) {
        let _ = exec_cmd("move", &[&self.exe, ".\\quarantine"], false)
            .unwrap()
            .wait();
        println!("Please revoke all execution access, or get this thing out of here");
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

pub fn get_interface_and_ip() -> Interface {
    loop {
        let mut interfaces: Vec<Interface> = get_if_addrs().unwrap().into_iter().collect();
        let mut i = 0;
        for interface in &interfaces {
            println!("{}) {} => {}", i, &interface.name, &interface.ip());
            i += 1;
        }
        print!("Select internet interface number: ");
        let _ = stdout().flush();
        let mut interface_id = String::new();
        stdin().read_line(&mut interface_id).unwrap();
        let selected_id: usize = match interface_id.trim().parse() {
            Ok(id) => id,
            Err(x) => {
                println!("{}", x);
                continue;
            }
        };
        return interfaces.remove(selected_id);
    }
}
