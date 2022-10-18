use crate::utils::tools::{exec_cmd, read_lines};
use log::error;
use std::io::Write;

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
        if !all_users_cmd.status.success() {
            error!("Failed to get AD Users!");
            return out;
        }
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
        if exec_cmd(
            "C:\\Windows\\System32\\net.exe",
            &["user", "/domain", &self.name, "/active:no"],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to disable domain user {}", &self.name);
        };
    }

    pub fn change_password(&self, password: &str) {
        if !exec_cmd(
            "C:\\Windows\\System32\\net.exe",
            &["user", "/domain", &self.name, password],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to change domain user {} password!", &self.name);
        }
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
        let fields_cmd = exec_cmd("C:\\Windows\\System32\\net.exe", &["user", &name], false)
            .unwrap()
            .wait_with_output()
            .unwrap();
        let fields_out = match fields_cmd.status.success() {
            true => fields_cmd.stdout,
            false => {
                error!("Failed to get local user info for {}", name);
                return None;
            }
        };
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
        let all_users_cmd = exec_cmd(
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
        .unwrap();
        let all_users_out = match all_users_cmd.status.success() {
            true => all_users_cmd.stdout,
            false => {
                error!("Failed to get local users!");
                return out;
            }
        };
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

    pub fn change_password(&self, password: &str) {
        if !exec_cmd(
            "C:\\Windows\\System32\\net.exe",
            &["user", &self.name, password],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to reset local user {} password", &self.name);
        }
    }

    pub fn shutdown(&self) {
        if !exec_cmd(
            "C:\\Windows\\System32\\net.exe",
            &["user", &self.name, "/active:no"],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to disable local user {}", &self.name);
        }
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
        if !exec_cmd("/usr/sbin/usermod", &["-L", &self.username], false)
            .unwrap()
            .wait()
            .unwrap()
            .success()
        {
            error!("Failed to lock user {} password", &self.username);
        };
        if !exec_cmd(
            "/usr/sbin/usermod",
            &["-s", "/bin/false", &self.username],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to lock user {} shell", &self.username);
        }
        if !exec_cmd(
            "/usr/bin/gpasswd",
            &["--delete", &self.username, "sudo"],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to remove sudo from user {}", &self.username);
        }
        if !exec_cmd(
            "/usr/bin/gpasswd",
            &["--delete", &self.username, "wheel"],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to remove wheel from user {}", &self.username);
        }
    }

    #[cfg(target_os = "freebsd")]
    pub fn shutdown(&self) {
        if !exec_cmd("/usr/sbin/pw", &["lock", &self.username], false)
            .unwrap()
            .wait()
            .unwrap()
            .success()
        {
            error!("Failed to lock user {} password", &self.username);
        }
        if !exec_cmd(
            "/usr/sbin/pw",
            &["usermod", "-s", "/bin/false", &self.username],
            false,
        )
        .unwrap()
        .wait()
        .unwrap()
        .success()
        {
            error!("Failed to lock user {} shell", &self.username);
        }
        if !exec_cmd("/usr/sbin/pw", &["wheel", "-d", &self.username], false)
            .unwrap()
            .wait()
            .unwrap()
            .success()
        {
            error!("Failed to remove wheel from user {}", &self.username);
        }
    }

    pub fn change_password(&self, password: &str) {
        let mut proc = exec_cmd("/usr/bin/passwd", &[&self.username], true).unwrap();
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
        if !proc.wait().unwrap().success() {
            error!("Failed to reset user {} password", &self.username);
        }
    }
}
