use dialoguer::{FuzzySelect, Input, theme::ColorfulTheme};
use rusqlite::{Connection, params};

// Import Custom Modules
use crate::helper;

pub fn generate_password(
    length: usize,
    uppercase: bool,
    numbers: bool,
    symbols: bool,
    word: bool,
    copy: bool,
) {
    if length < 8 {
        println!("[Warning]: Password requested less than 8 characters.... Not secure, giving up.");
        std::process::exit(1);
    }
    let password = if word {
        helper::generate_word_passphrase(length, uppercase, numbers, symbols)
    } else {
        helper::generate_secure_password(length, uppercase, numbers, symbols)
    };
    if copy {
        helper::copy_to_clipboard(&password);
    } else {
        println!("{}", password);
    }
}

pub fn run_interactive(conn: &Connection, master_password: &str) {
    let theme = ColorfulTheme::default();
    loop {
        let keys = helper::get_all_keys(conn);
        let mut options = vec!["[Create New Key]".to_string()];
        options.extend(keys.clone());
        options.push("[Exit]".to_string());

        println!("\n--- Interactive Mode ---");
        let selection = match FuzzySelect::with_theme(&theme)
            .with_prompt("Type to filter options.")
            .items(&options)
            .default(0)
            .interact_opt()
        {
            Ok(Some(index)) => index,
            _ => break,
        };
        if selection == 0 {
            // Create New Key
            helper::create_key_prompt(conn, master_password);
        } else if selection == options.len() - 1 {
            break;
        } else {
            if let Some(selected_key) = keys.get(selection - 1) {
                let selected_key = selected_key.trim();
                // Manage Existing Key
                helper::manage_existing_key(conn, selected_key, master_password);
            }
        }
    }
}

pub fn run_read(conn: &Connection, key: Option<String>, master_password: &str, copy: bool) {
    let theme = ColorfulTheme::default();

    let key = match key {
        Some(k) => k,
        None => match Input::<String>::with_theme(&theme)
            .with_prompt("Enter key to read")
            .interact_text()
        {
            Ok(k) => k,
            Err(_) => return,
        },
    };

    let mut select = match conn.prepare("SELECT nonce, encrypted_value FROM store WHERE key = ?") {
        Ok(s) => s,
        Err(e) => {
            println!("[Error]: Database system failure: {e}");
            return;
        }
    };

    let result = select.query_row(params![key], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    });

    match result {
        Ok((nonce, encrypted_value)) => {
            match helper::decrypt(&key, &encrypted_value, &nonce, master_password) {
                Some(decrypted) => {
                    if copy {
                        helper::copy_to_clipboard(&decrypted);
                    } else {
                        println!("{key}: {decrypted}");
                    }
                }
                None => println!("[Error]: Decryption failed. Corrupted block or cipher mismatch."),
            }
        }
        Err(_) => println!("[Error]: Key '{key}' not found in database."),
    }
}
