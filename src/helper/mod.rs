use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use clipboard::{ClipboardContext, ClipboardProvider};
use dialoguer::{Confirm, FuzzySelect, Input, Password, theme::ColorfulTheme};
use homedir::my_home;
use rand::{Rng, RngExt};
use rusqlite::{Connection, params};
use std::{io::Result, path::PathBuf};

fn capitalize_first(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().to_string() + chars.as_str(),
    }
}

pub fn copy_to_clipboard(value: &str) {
    let mut ctx: ClipboardContext = match ClipboardProvider::new() {
        Ok(c) => c,
        Err(e) => {
            println!("[Error]: Failed to access clipboard: {e}");
            return;
        }
    };
    if let Err(e) = ctx.set_contents(value.to_owned()) {
        println!("[Error]: Failed to copy to clipboard: {e}");
    } else {
        println!("[Success]: Copied to clipboard.");
    }
}

pub fn create_key_prompt(conn: &Connection, master_password: &str) {
    let theme = ColorfulTheme::default();
    let key: String = match Input::with_theme(&theme)
        .with_prompt("Enter a new key name")
        .interact_text()
    {
        Ok(k) => k,
        Err(_) => return,
    };
    key.trim().to_string();

    let sql_check = "SELECT EXISTS(SELECT 1 FROM store WHERE key = ?1)";
    let exists: bool = match conn.query_row(sql_check, params![key], |row| row.get(0)) {
        Ok(found) => found,
        Err(_) => {
            println!("[Error]: Failed to query database for key existence.");
            return;
        }
    };

    if exists {
        println!(
            "[Warning]: Key '{}' already exists. Creation cancelled.",
            key
        );
        return;
    }

    let value: String = match Password::with_theme(&theme)
        .with_prompt("Enter Password")
        .interact()
    {
        Ok(v) => v,
        Err(_) => return,
    };

    let confirm_value: String = match Password::with_theme(&theme)
        .with_prompt("Confirm Password")
        .interact()
    {
        Ok(v) => v,
        Err(_) => return,
    };

    if value != confirm_value {
        println!("[Warning]: Passwords do not match. Key creation cancelled.");
        return;
    }

    let (nonce, encrypted) = match encrypt(&key, &value, master_password) {
        Some(pair) => pair,
        None => {
            println!("[Error]: Encryption runtime failed.");
            return;
        }
    };
    let sql = "INSERT INTO store (key, nonce, encrypted_value) VALUES (?1, ?2, ?3)";
    match conn.execute(sql, params![key, nonce, encrypted]) {
        Ok(_) => println!("[Success]: Successfully saved '{}'.", key),
        Err(_) => println!(
            "[Error]: Key '{}' already exists or database disk write failed.",
            key
        ),
    };
}

pub fn decrypt(
    key: &str,
    encrypted_value: &[u8],
    nonce_bytes: &[u8],
    password: &str,
) -> Option<String> {
    let key_bytes = derive_key(key, password)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted_bytes = cipher.decrypt(nonce, encrypted_value).ok()?;
    String::from_utf8(decrypted_bytes).ok()
}

fn derive_key(key: &str, password: &str) -> Option<[u8; 32]> {
    let salt = format!("{}-GlazaLock", key.trim());
    let salt = SaltString::encode_b64(&salt.as_bytes());
    let salt = match salt {
        Ok(s) => s,
        Err(e) => {
            println!(
                "[Error]: Failed to create salt string from key '{}': {}",
                key, e
            );
            return None;
        }
    };
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt);
    let password_hash = match password_hash {
        Ok(h) => h,
        Err(e) => {
            println!("[Error]: Failed to hash password for key '{}': {}", key, e);
            return None;
        }
    };
    let mut key_bytes = [0u8; 32];
    let hash = password_hash.hash?;
    let hash_bytes = hash.as_bytes();
    if hash_bytes.len() < 32 {
        println!("[Error]: Derived key hash is too short.");
        return None;
    }
    key_bytes.copy_from_slice(&hash_bytes[..32]);
    Some(key_bytes)
}

fn encrypt(key: &str, value: &str, password: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let key_bytes = derive_key(key, password)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_value = cipher.encrypt(nonce, value.as_bytes()).ok()?;
    Some((nonce_bytes.to_vec(), encrypted_value))
}

pub fn generate_secure_password(
    length: usize,
    uppercase: bool,
    numbers: bool,
    symbols: bool,
) -> String {
    let mut base_charset = String::from("abcdefghijklmnopqrstuvwxyz");
    if uppercase {
        base_charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    if base_charset.is_empty() {
        base_charset.push_str("abcdefghijklmnopqrstuvwxyz"); // Default to lowercase if no options selected
    }
    let mut full_charset = base_charset.clone();
    if symbols {
        full_charset.push_str("!@#$%^&*()-_=+[]{}|;:,.<>?");
    }
    if numbers {
        full_charset.push_str("0123456789");
    }

    let base_chars: Vec<char> = base_charset.chars().collect();
    let full_chars: Vec<char> = full_charset.chars().collect();

    let mut rng = rand::rng();
    let mut password = String::with_capacity(length);

    if length > 0 {
        let first_idx = rng.random_range(0..base_chars.len());
        password.push(base_chars[first_idx]);
    }

    if length == 1 {
        return password;
    }

    for _ in 1..length {
        let idx = rng.random_range(0..full_chars.len());
        password.push(full_chars[idx] as char);
    }
    password
}

pub fn generate_word_passphrase(
    length: usize,
    uppercase: bool,
    numbers: bool,
    symbols: bool,
) -> String {
    let mut rng = rand::rng();
    let mut chosen_words: Vec<String> = Vec::new();

    loop {
        let current_total: usize = chosen_words.iter().map(|w| w.len()).sum();
        let separators_len = if chosen_words.is_empty() {
            0
        } else {
            chosen_words.len() - 1
        };
        let current_passphrase_len = current_total + separators_len;

        if current_passphrase_len >= length {
            break;
        }

        let next_separator_cost = if chosen_words.is_empty() { 0 } else { 1 };

        if current_passphrase_len + next_separator_cost >= length {
            break;
        }

        let remaining_length = length - (current_passphrase_len + next_separator_cost);

        if remaining_length <= 3 {
            let random_garbage =
                generate_secure_password(remaining_length, uppercase, numbers, symbols);
            chosen_words.push(random_garbage);
            break; // Garbage fills the last of the length, so we are done
        }

        let mut target_word_len = rng.random_range(4..=6);
        if target_word_len > remaining_length {
            target_word_len = remaining_length;
        }

        let word = get_random_word_with_length(target_word_len);
        let mut word: String = match word {
            None => "".to_string(),
            Some(w) => w.to_string(),
        };

        if numbers && word.len() < remaining_length {
            let random_digit = rng.random_range(0..10).to_string();
            word.push_str(&random_digit);
        }

        if symbols && word.len() < remaining_length {
            let symbols_charset = "!@#$%^&*()-_=+[]{}|;:,.<>?";
            let symbols_chars: Vec<char> = symbols_charset.chars().collect();
            let symbol_idx = rng.random_range(0..symbols_chars.len());
            word.push(symbols_chars[symbol_idx]);
        }

        if uppercase && rng.random::<bool>() {
            word = capitalize_first(&word);
        }

        if !word.is_empty() {
            chosen_words.push(word);
        } else {
            let fallback_garbage =
                generate_secure_password(remaining_length, uppercase, numbers, symbols);
            chosen_words.push(fallback_garbage);
            break;
        }
    }

    let mut passphrase = chosen_words.join("-");
    passphrase = if passphrase.len() < length {
        format!("{}-", passphrase)
    } else {
        passphrase
    };

    if uppercase && !passphrase.chars().any(|c| c.is_uppercase()) {
        passphrase = capitalize_first(&passphrase);
    }

    passphrase
}

pub fn get_all_keys(conn: &Connection) -> Vec<String> {
    let sql = "SELECT key FROM store";
    let mut select = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let key_iterator = match select.query_map([], |row| row.get::<_, String>(0)) {
        Ok(iterator) => iterator,
        Err(_) => return Vec::new(),
    };

    key_iterator
        .filter_map(|key| key.ok())
        .map(|key_str| format!("\t{}", key_str))
        .collect()
}

pub fn get_db_path() -> Result<PathBuf> {
    let mut db_path = get_home_dir()?;
    db_path.push(".gl.db");
    Ok(db_path)
}

pub fn get_home_dir() -> Result<PathBuf> {
    let home = match my_home() {
        Ok(opt) => match opt {
            Some(path) => path,
            None => {
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("ERROR: Could not get home directory: {}", e);
            std::process::exit(1);
        }
    };
    Ok(home)
}

pub fn get_random_word_with_length(target_length: usize) -> Option<&'static str> {
    let word_pool = random_word::all_len(target_length, random_word::Lang::En);
    let word_pool = match word_pool {
        Some(pool) => pool,
        None => &Vec::new(),
    };
    if word_pool.is_empty() {
        return None;
    }
    let mut rng = rand::rng();
    let idx = rng.random_range(0..word_pool.len());

    Some(word_pool[idx])
}

pub fn handle_authentication(conn: &Connection) -> Option<String> {
    let theme = ColorfulTheme::default();
    let sql = "SELECT password_hash FROM config WHERE id = 1";
    let mut select = conn.prepare(sql).ok()?;
    let stored_hash_res = select.query_row([], |row| row.get::<_, String>(0));

    let argon2 = Argon2::default();
    match stored_hash_res {
        Ok(stored_hash) => {
            println!("--- Secure Authentication ---");
            let password = Password::with_theme(&theme)
                .with_prompt("Enter Master Password to unlock")
                .interact()
                .ok()?;

            let parsed_hash = PasswordHash::new(&stored_hash.as_str()).ok()?;
            if argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                Some(password)
            } else {
                eprintln!("[Error]: Invalid master password. Access denied.");
                None
            }
        }
        Err(_) => {
            println!("--- Master Password Setup ---");
            println!("No master password detected. Please configure one now.");

            let password = Password::with_theme(&theme)
                .with_prompt("Create Master Password")
                .interact()
                .ok()?;

            let confirm_password = Password::with_theme(&theme)
                .with_prompt("Confirm Master Password")
                .interact()
                .ok()?;

            if password != confirm_password {
                eprintln!("[Error]: Passwords do not match. Restart application to retry.");
                return None;
            }

            let mut salt_bytes = [0u8; 16];
            rand::rng().fill_bytes(&mut salt_bytes);
            let salt = SaltString::encode_b64(&salt_bytes).ok()?;

            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .ok()?
                .to_string();

            if conn
                .execute(
                    "INSERT INTO config (id, password_hash) VALUES (1, ?1)",
                    params![password_hash],
                )
                .is_err()
            {
                eprintln!("Error: Critical failure saving master signature.");
                return None;
            }

            println!("Master Password set successfully! Database unlocked.");
            Some(password)
        }
    }
}

pub fn manage_existing_key(conn: &Connection, key: &str, master_password: &str) {
    let theme = ColorfulTheme::default();
    let actions = vec!["View", "Edit", "Copy", "Delete", "Back"];

    let selection = match FuzzySelect::with_theme(&theme)
        .with_prompt(format!("Managing key: {key}"))
        .items(&actions)
        .default(0)
        .interact_opt()
    {
        Ok(Some(index)) => index,
        _ => return,
    };

    match selection {
        0 => {
            // View
            let sql = "SELECT nonce, encrypted_value FROM store WHERE key = ?1";
            let mut select = match conn.prepare(sql) {
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
                Ok((nonce, encrypted)) => {
                    if let Some(decrypted) = decrypt(key, &encrypted, &nonce, master_password) {
                        println!("{key}: {}", decrypted);
                    } else {
                        println!(
                            "[Error]: Decryption failed. Possible causes: Incorrect master password or data corruption."
                        );
                    }
                }
                Err(e) => println!("[Error]: Failed to retrieve key data: {e}"),
            }
            std::process::exit(0);
        }
        1 => {
            // Edit
            let new_value: String = match Input::with_theme(&theme)
                .with_prompt("Enter new value")
                .interact_text()
            {
                Ok(v) => v,
                Err(_) => return,
            };
            let (nonce, encrypted) = match encrypt(key, &new_value, master_password) {
                Some(pair) => pair,
                None => {
                    println!("[Error]: Key derivation failed.");
                    return;
                }
            };

            let sql = "UPDATE store SET nonce = ?1, encrypted_value = ?2 WHERE key = ?3";
            if let Err(e) = conn.execute(sql, params![nonce, encrypted, key]) {
                println!("[Error]: Could not update the entry: {e}");
            } else {
                println!("[Success]: Updated '{key}'.");
            }
            std::process::exit(0);
        }
        2 => {
            // Copy
            let sql = "SELECT nonce, encrypted_value FROM store WHERE key = ?1";
            let mut select = match conn.prepare(sql) {
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
                Ok((nonce, encrypted)) => {
                    if let Some(decrypted) = decrypt(key, &encrypted, &nonce, master_password) {
                        copy_to_clipboard(&decrypted);
                    } else {
                        println!(
                            "[Error]: Decryption failed. Possible causes: Incorrect master password or data corruption."
                        );
                    }
                }
                Err(e) => println!("[Error]: Failed to retrieve key data: {e}"),
            }
            std::process::exit(0);
        }
        3 => {
            // Delete
            let confirm = Confirm::with_theme(&theme)
                .with_prompt(format!("Are you sure you want to delete '{key}'?"))
                .interact();

            let confirm = match confirm {
                Ok(c) => c,
                Err(_) => false,
            };

            if confirm {
                let sql = "DELETE FROM store WHERE key = ?1";
                if let Err(e) = conn.execute(sql, params![key]) {
                    println!("[Error]: Failed to delete row: {e}");
                } else {
                    println!("[Success]: Deleted '{key}'.");
                }
            }
            std::process::exit(0);
        }
        _ => {}
    }
}
