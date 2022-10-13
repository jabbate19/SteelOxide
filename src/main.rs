use clap::{App, SubCommand};

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "freebsd", path = "freebsd/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
pub mod os;
pub mod utils;

fn main() {
    let app = App::new("SteelOxide")
        .author("Joe Abbate, joe.abbate@mail.rit.edu")
        .version("1.0.0")
        .about("Defends Linux Boxes against Malicious Scripts")
        .subcommand(SubCommand::with_name("setup").about("Used to Setup Initial Environement"))
        .subcommand(
            SubCommand::with_name("tracker").about("Scan network traffic for malicious sessions"),
        )
        .subcommand(SubCommand::with_name("revive").about("Red Teamn't"))
        .subcommand(SubCommand::with_name("persistnt").about("Scan for persistence"))
        .get_matches();

    match app.subcommand_name() {
        None => println!("No Subcommand Provided!"),
        Some("setup") => os::setup::main().unwrap(),
        Some("tracker") => os::tracker::main().unwrap(),
        Some("revive") => os::revive::main().unwrap(),
        Some("persistnt") => os::persistnt::main().unwrap(),
        Some(x) => println!("Unknown Command: {}", x),
    };
}
