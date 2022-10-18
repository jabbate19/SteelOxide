# BlueTeamRust (SteelOxide)
## A Blue Team Binary to Assist teams defend systems on Windows, Linux, and PfSense plattforms

# Features
* User Auditing
* Firewall Configuration
* Service Maintaining
* Cron/Scheduled Task Auditing
* File Integrity Checks
* File Permission Checks
* Resetting common config files
* Network Traffic Monitoring
* Malicious File Quarantine

# Usage
Note: `BINARY` will be used in place of `./steeloxide` or `.\steeloxide.exe` for respective systems
1. Download the binary for the needed OS (Windows, Linux, PfSense)
2. Run `BINARY setup` to begin initialization process
3. Save `config.json` and other created files in a secure location in case it is altered (Screenshot them for reports)
4. Run `BINARY tracker` to begin tracking network connections. Those that appear malicious should be terminated/quarantined, then reported
5. Run `BINARY revive` in the directory of the `config.json` file to attempt to bring back services when they happen to go down. This will not catch all breaks, but can solve the common/generic ones (Firewall, Service Stop)

# Contributing
Feel free to make a PR/Issue. I'm a college student trying to write funcitonal software and would love some help/advice

# File Structure
* src/main.rs
  * Starts application and makes call to needed subcommand
* src/utils/
  * Contains common structs and functions that are used by multiple files for commands
* src/`OPERATING_SYSTEM`/
  * Contains subcommand functions for respective OS.
  * Used directory is selected at compile time by `cfg_attr` usage in `main.rs`

# Message to Red Team
Hi :) Please don't delete me, or I'll be sad :(