use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use dialoguer::{FuzzySelect, Input, Password, theme::ColorfulTheme};
use rand::Rng;
use rusqlite::{Connection, Transaction, TransactionBehavior, params};

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

pub fn reset_master_password(conn: &Connection, master_password: &str) {
    let theme = ColorfulTheme::default();
    let argon2 = Argon2::default();
    println!("--- Reset Master Password ---");
    let new_master_password = match Password::with_theme(&theme)
        .with_prompt("Enter NEW Master Password")
        .interact()
    {
        Ok(p) => p,
        Err(_) => return,
    };
    let confirm_master_password = match Password::with_theme(&theme)
        .with_prompt("Confirm NEW Master Password")
        .interact()
    {
        Ok(p) => p,
        Err(_) => return,
    };

    if new_master_password == master_password {
        eprintln!("[ERROR]: New password cannot be identical to your current password.");
        return;
    }

    if new_master_password != confirm_master_password {
        eprintln!("[ERROR]: Passwords do not match. Reset aborted.");
        return;
    }

    println!("Re-encrypting database vault secrets... Do not close the application.");

    let tx = match Transaction::new_unchecked(conn, TransactionBehavior::Deferred) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[Error]: Failed to open transaction frame: {}", e);
            return;
        }
    };
    let sql = "SELECT * FROM store";
    let mut select = match tx.prepare(sql) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[ERROR]: Failed to prepare data scanning operation.");
            return;
        }
    };

    let rows = match select.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    }) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("[ERROR]: Failed to query storage elements.");
            return;
        }
    };
    let mut migrated_entries = Vec::new();

    for row in rows {
        if let Ok((key, nonce, encrypted_value)) = row {
            let decrypted_password =
                match helper::decrypt(&key, &encrypted_value, &nonce, master_password) {
                    Some(decrypted) => decrypted,
                    None => {
                        println!("[ERROR]: Decryption failed. Corrupted block or cipher mismatch.");
                        return;
                    }
                };
            // Some((nonce_bytes.to_vec(), encrypted_value))
            let (new_nonce, encrypted_password) =
                match helper::encrypt(&key, &decrypted_password, &new_master_password) {
                    Some(pair) => pair,
                    None => {
                        return;
                    }
                };

            migrated_entries.push((key, new_nonce, encrypted_password));
        }
    }
    drop(select);
    for (key, nonce, encrypted_password) in migrated_entries {
        let sql = "UPDATE store SET nonce = ?1, encrypted_value = ?2 WHERE key = ?3";
        if tx
            .execute(sql, params![nonce, encrypted_password, key])
            .is_err()
        {
            eprintln!("[CRITICAL]: Failed to save re-encrypted record block. Aborting.");
            return;
        }
    }
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = match SaltString::encode_b64(&salt_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    let password_hash = match argon2.hash_password(new_master_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return,
    };

    let hash_sql = "UPDATE config SET password_hash = ?1 WHERE id = 1";
    if tx.execute(hash_sql, params![password_hash]).is_err() {
        eprintln!("[CRITICAL]: Failed to update system configuration keys. Aborting transaction.");
        return;
    }

    match tx.commit() {
        Ok(_) => println!("[SUCCESS]: Master password updated."),
        Err(e) => eprintln!(
            "[ERROR]: Failed to write updates permently to disk safely: {}",
            e
        ),
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
