use crate::utils::config::SysConfig;
use get_if_addrs::{get_if_addrs, Interface};
use std::process::{Command, Stdio};
use std::{
    fs::File,
    io::{self, stdin, stdout, BufRead, Write},
    path::Path,
    process::Child,
};

pub fn verify_config(config: SysConfig) -> bool {
    println!("{:?}", config);
    yes_no("Config Ok".to_owned())
}

pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
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
