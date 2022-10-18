use clap::{App, SubCommand};

use chrono::prelude::*;
use simplelog::*;

use std::fs::File;

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "freebsd", path = "freebsd/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
pub mod os;
pub mod utils;

fn main() {
    let app = App::new("SteelOxide")
        .author("Joe Abbate, joe.abbate@mail.rit.edu")
        .version("1.0.0")
        .about("Defends Linux, Windows, and PfSense devices against Malicious Actors")
        .subcommand(SubCommand::with_name("setup").about("Used to Setup Initial Environement"))
        .subcommand(
            SubCommand::with_name("tracker").about("Scan network traffic for malicious sessions"),
        )
        .subcommand(SubCommand::with_name("revive").about("Red Teamn't"))
        .subcommand(SubCommand::with_name("persistnt").about("Scan for persistence"))
        .get_matches();

    let dt = Local::now();

    match app.subcommand_name() {
        None => println!("No Subcommand Provided!"),
        Some("setup") => {
            CombinedLogger::init(vec![
                TermLogger::new(
                    LevelFilter::Info,
                    Config::default(),
                    TerminalMode::Mixed,
                    ColorChoice::Auto,
                ),
                WriteLogger::new(
                    LevelFilter::Info,
                    Config::default(),
                    File::create(&format!(
                        "steeloxide_setup_{}.log",
                        dt.format("%Y_%m_%d_%H_%M_%S").to_string()
                    ))
                    .unwrap(),
                ),
            ])
            .unwrap();
            os::setup::main().unwrap()
        }
        Some("tracker") => {
            CombinedLogger::init(vec![
                TermLogger::new(
                    LevelFilter::Info,
                    Config::default(),
                    TerminalMode::Mixed,
                    ColorChoice::Auto,
                ),
                WriteLogger::new(
                    LevelFilter::Info,
                    Config::default(),
                    File::create(&format!(
                        "steeloxide_tracker_{}.log",
                        dt.format("%Y_%m_%d_%H_%M_%S").to_string()
                    ))
                    .unwrap(),
                ),
            ])
            .unwrap();
            os::tracker::main().unwrap()
        }
        Some("revive") => {
            CombinedLogger::init(vec![
                TermLogger::new(
                    LevelFilter::Info,
                    Config::default(),
                    TerminalMode::Mixed,
                    ColorChoice::Auto,
                ),
                WriteLogger::new(
                    LevelFilter::Info,
                    Config::default(),
                    File::create(&format!(
                        "steeloxide_revive_{}.log",
                        dt.format("%Y_%m_%d_%H_%M_%S").to_string()
                    ))
                    .unwrap(),
                ),
            ])
            .unwrap();
            os::revive::main().unwrap()
        }
        Some("persistnt") => {
            CombinedLogger::init(vec![
                TermLogger::new(
                    LevelFilter::Info,
                    Config::default(),
                    TerminalMode::Mixed,
                    ColorChoice::Auto,
                ),
                WriteLogger::new(
                    LevelFilter::Info,
                    Config::default(),
                    File::create(&format!(
                        "steeloxide_persistnt_{}.log",
                        dt.format("%Y_%m_%d_%H_%M_%S").to_string()
                    ))
                    .unwrap(),
                ),
            ])
            .unwrap();
            os::persistnt::main().unwrap()
        }
        Some(x) => println!("Unknown Command: {}", x),
    };
}
