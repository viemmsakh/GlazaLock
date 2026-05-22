use clap::Parser;
use rusqlite::Connection;
use std::io::Result;

// Custom Modules
mod commands;
mod helper;
mod structs;
use structs::{Cli, Commands, PRINTSTATUS};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db_path = helper::get_db_path()?;
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            helper::print_message(
                PRINTSTATUS::ERROR,
                format!("Error: Failed to open SQLite database: {}", e),
            );
            std::process::exit(1);
        }
    };

    // Create config in database if not exists
    if let Err(e) = conn.execute(
        "CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL
        )",
        [],
    ) {
        helper::print_message(
            PRINTSTATUS::ERROR,
            format!("Error: Failed to initialize config table: {}", e),
        );
        std::process::exit(1);
    }

    // Create store table if not exists
    if let Err(e) = conn.execute(
        "CREATE TABLE IF NOT EXISTS store (
            key TEXT PRIMARY KEY,
            nonce BLOB NOT NULL,
            encrypted_value BLOB NOT NULL
        )",
        [],
    ) {
        helper::print_message(
            PRINTSTATUS::ERROR,
            format!("Failed to initialize data table: {}", e),
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
            if let Some(master_password) = helper::handle_authentication(&conn) {
                commands::run_interactive(&conn, &master_password);
            }
        }
        Some(Commands::Read { key, copy }) => {
            if let Some(master_password) = helper::handle_authentication(&conn) {
                commands::run_read(&conn, key, &master_password, copy);
            }
        }
        Some(Commands::Reset) => {
            if let Some(master_password) = helper::handle_authentication(&conn) {
                commands::reset_master_password(&conn, &master_password);
            }
        }
        None => {
            if let Some(master_password) = helper::handle_authentication(&conn) {
                commands::run_interactive(&conn, &master_password);
            }
        }
    }

    Ok(())
}
