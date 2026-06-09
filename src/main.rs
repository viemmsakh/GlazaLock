use clap::Parser;
use std::{fs::create_dir_all, io::Result};

// Custom Modules
mod commands;
mod helper;
mod structs;
use structs::{Cli, Commands, PRINTSTATUS};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup and verify structural workspace directories (~/.glock/keys/)
    let keys_dir = helper::get_keys_dir()?;

    if let Err(e) = create_dir_all(&keys_dir) {
        helper::print_message(
            PRINTSTATUS::ERROR,
            format!(
                "Error: Failed to construct environment layout workspace on disk: {}",
                e
            ),
        );
        std::process::exit(1);
    }

    match cli.command {
        Some(Commands::Generate {
            length,
            uppercase,
            numbers,
            symbols,
            word,
            copy,
        }) => {
            commands::generate_password(length, uppercase, numbers, symbols, word, copy);
        }
        Some(Commands::Interactive) => {
            if let Some(master_password) = helper::handle_authentication() {
                commands::run_interactive(&master_password);
            }
        }
        Some(Commands::Read { key, copy }) => {
            if let Some(master_password) = helper::handle_authentication() {
                commands::run_read(key, &master_password, copy);
            }
        }
        Some(Commands::Reset) => {
            if let Some(master_password) = helper::handle_authentication() {
                commands::reset_master_password(&master_password);
            }
        }
        None => {
            if let Some(master_password) = helper::handle_authentication() {
                commands::run_interactive(&master_password);
            }
        }
    }

    Ok(())
}
