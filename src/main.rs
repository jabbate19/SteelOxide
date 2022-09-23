use clap::{App, SubCommand};

pub mod commands;
pub mod utils;

fn main() {
    let app = App::new("SteelOxide")
        .author("Joe Abbate, joe.abbate@mail.rit.edu")
        .version("1.0.0")
        .about("Defends Linux Boxes against Malicious Scripts")
        .subcommand(SubCommand::with_name("setup").about("Used to Setup Initial Environement"))
        .subcommand(
            SubCommand::with_name("ssplus").about("Scan network traffic for malicious sessions"),
        )
        .subcommand(SubCommand::with_name("revive").about("Red Teamn't"))
        .subcommand(SubCommand::with_name("persistnt").about("Scan for persistence"))
        .get_matches();

    match app.subcommand_name() {
        None => println!("Chom"),
        Some("setup") => commands::setup::main().unwrap(),
        Some("ssplus") => commands::ssplus::main().unwrap(),
        Some(x) => println!("{}", x),
    };
}
