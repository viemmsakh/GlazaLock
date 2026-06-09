use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64ct::{Base64, Encoding};
use clipboard::{ClipboardContext, ClipboardProvider};
use colored::*;
use dialoguer::{Confirm, FuzzySelect, Input, Password, theme::ColorfulTheme};
use homedir::my_home;
use rand::{Rng, RngExt};
use std::fs::{File, read_dir, read_to_string, remove_file, write};
use std::io::{Read, Result};
use std::path::PathBuf;

// Import Custom Flat-File Structs and Status Enums
use crate::structs::{AppConfig, EncryptedRecord, PRINTSTATUS};

fn capitalize_first(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().to_string() + chars.as_str(),
    }
}

pub fn clear_screen() {
    let clear = clearscreen::clear();
    match clear {
        Ok(()) => {}
        Err(e) => print_message(PRINTSTATUS::WARN, format!("Unable to clear screen: {}", e)),
    }
}

pub fn copy_to_clipboard(value: &str) {
    let mut ctx: ClipboardContext = match ClipboardProvider::new() {
        Ok(c) => c,
        Err(e) => {
            print_message(
                PRINTSTATUS::ERROR,
                format!("Failed to access clipboard: {}", e),
            );
            return;
        }
    };
    if let Err(e) = ctx.set_contents(value.to_owned()) {
        print_message(
            PRINTSTATUS::ERROR,
            format!("Failed to copy to clipboard: {}", e),
        );
    } else {
        print_message(PRINTSTATUS::SUCCESS, format!("Copied to clipboard."));
    }
}

pub fn create_key_prompt(master_password: &str) {
    let theme = ColorfulTheme::default();
    let key: String = match Input::<String>::with_theme(&theme)
        .with_prompt("Enter a new key name")
        .interact_text()
    {
        Ok(k) => k.trim().to_string(),
        Err(_) => return,
    };

    let mut key_file_path = match get_keys_dir() {
        Ok(p) => p,
        Err(_) => return,
    };
    key_file_path.push(&key);

    if key_file_path.exists() {
        print_message(
            PRINTSTATUS::WARN,
            format!("Key '{}' already exists. Creation cancelled.", key),
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
        print_message(
            PRINTSTATUS::WARN,
            format!("Passwords do not match. Key creation cancelled."),
        );
        return;
    }

    let (nonce_bytes, encrypted_bytes) = match encrypt(&key, &value, master_password) {
        Some(pair) => pair,
        None => {
            print_message(PRINTSTATUS::ERROR, format!("Encryption runtime failed."));
            return;
        }
    };

    // Serialize binary byte blocks into secure, standard readable Base64 Strings
    let record = EncryptedRecord {
        nonce: Base64::encode_string(&nonce_bytes),
        encrypted_value: Base64::encode_string(&encrypted_bytes),
    };

    if let Ok(serialized) = serde_json::to_string_pretty(&record) {
        if write(key_file_path, serialized).is_ok() {
            print_message(
                PRINTSTATUS::SUCCESS,
                format!("Successfully saved '{}'.", key),
            );
            return;
        }
    }
    print_message(PRINTSTATUS::ERROR, format!("Flat-file write failed."));
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
            print_message(
                PRINTSTATUS::ERROR,
                format!("Failed to create salt string from key '{}': {}", key, e,),
            );
            return None;
        }
    };
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt);
    let password_hash = match password_hash {
        Ok(h) => h,
        Err(e) => {
            print_message(
                PRINTSTATUS::ERROR,
                format!("Failed to hash password for key '{}': {}", key, e),
            );
            return None;
        }
    };
    let mut key_bytes = [0u8; 32];
    let hash = password_hash.hash?;
    let hash_bytes = hash.as_bytes();
    if hash_bytes.len() < 32 {
        print_message(
            PRINTSTATUS::ERROR,
            format!("Derived key hash is too short."),
        );
        return None;
    }
    key_bytes.copy_from_slice(&hash_bytes[..32]);
    Some(key_bytes)
}

pub fn encrypt(key: &str, value: &str, password: &str) -> Option<(Vec<u8>, Vec<u8>)> {
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
        base_charset.push_str("abcdefghijklmnopqrstuvwxyz");
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
            break;
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

pub fn get_glock_dir() -> Result<PathBuf> {
    let mut path = get_home_dir()?;
    path.push(".glock");
    Ok(path)
}

pub fn get_keys_dir() -> Result<PathBuf> {
    let mut path = get_glock_dir()?;
    path.push("keys");
    Ok(path)
}

pub fn get_config_path() -> Result<PathBuf> {
    let mut path = get_glock_dir()?;
    path.push("config.json");
    Ok(path)
}

pub fn get_all_keys() -> Vec<String> {
    let keys_dir = match get_keys_dir() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    if let Ok(entries) = read_dir(keys_dir) {
        entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .map(|name| format!("\t{}", name))
            .collect()
    } else {
        Vec::new()
    }
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
            print_message(
                PRINTSTATUS::ERROR,
                format!("Could not get home directory: {}", e),
            );
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

pub fn handle_authentication() -> Option<String> {
    let theme = ColorfulTheme::default();
    let config_path = get_config_path().ok()?;
    let argon2 = Argon2::default();

    if config_path.exists() {
        let mut file = File::open(&config_path).ok()?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).ok()?;
        let config: AppConfig = serde_json::from_str(&contents).ok()?;

        print_message(PRINTSTATUS::INFO, format!("--- Secure Authentication ---"));
        let password = Password::with_theme(&theme)
            .with_prompt("Enter Master Password to unlock")
            .interact()
            .ok()?;

        let parsed_hash = PasswordHash::new(&config.password_hash).ok()?;
        if argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            Some(password)
        } else {
            print_message(
                PRINTSTATUS::ERROR,
                format!("Invalid master password. Access denied."),
            );
            None
        }
    } else {
        let keys_dir = get_keys_dir().ok()?;
        let store_count = read_dir(keys_dir).map(|d| d.count()).unwrap_or(0);

        if store_count > 0 {
            print_message(
                PRINTSTATUS::ERROR,
                format!("Critical Integrity Violation Detected!"),
            );
            print_message(
                PRINTSTATUS::ERROR,
                format!(
                    "Authentication has been locked down to protect data integrity. Operation aborted."
                ),
            );
            return None;
        }
        print_message(PRINTSTATUS::INFO, format!("--- Master Password Setup ---"));
        print_message(
            PRINTSTATUS::SUCCESS,
            format!("No master password detected. Please configure one now."),
        );

        let password = Password::with_theme(&theme)
            .with_prompt("Create Master Password")
            .interact()
            .ok()?;

        let confirm_password = Password::with_theme(&theme)
            .with_prompt("Confirm Master Password")
            .interact()
            .ok()?;

        if password != confirm_password {
            print_message(
                PRINTSTATUS::ERROR,
                format!("Passwords do not match. Restart application to retry."),
            );
            return None;
        }

        let mut salt_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut salt_bytes);
        let salt = SaltString::encode_b64(&salt_bytes).ok()?;

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .ok()?
            .to_string();

        let new_config = AppConfig { password_hash };
        if let Ok(serialized) = serde_json::to_string_pretty(&new_config) {
            if write(config_path, serialized).is_ok() {
                print_message(
                    PRINTSTATUS::SUCCESS,
                    format!("Master Password set successfully! Database unlocked."),
                );
                return Some(password);
            }
        }

        print_message(
            PRINTSTATUS::ERROR,
            format!("Critical failure saving master signature."),
        );
        None
    }
}

pub fn manage_existing_key(key: &str, master_password: &str) {
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

    let mut key_file_path = match get_keys_dir() {
        Ok(p) => p,
        Err(_) => return,
    };
    key_file_path.push(key);

    match selection {
        0 => {
            // View
            clear_screen();
            if let Ok(contents) = read_to_string(&key_file_path) {
                if let Ok(record) = serde_json::from_str::<EncryptedRecord>(&contents) {
                    let nonce_bytes = Base64::decode_vec(&record.nonce).ok();
                    let encrypted_bytes = Base64::decode_vec(&record.encrypted_value).ok();

                    if let (Some(n_bytes), Some(e_bytes)) = (nonce_bytes, encrypted_bytes) {
                        if let Some(decrypted) = decrypt(key, &e_bytes, &n_bytes, master_password) {
                            print_message(PRINTSTATUS::SUCCESS, format!("{key}: {}", decrypted));
                            return;
                        }
                    }
                }
            }
            print_message(
                PRINTSTATUS::ERROR,
                format!(
                    "Decryption failed. Possible causes: Incorrect master password or data corruption."
                ),
            );
        }
        1 => {
            // Edit
            let new_value: String = match Password::with_theme(&theme)
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

            if new_value != confirm_value {
                print_message(
                    PRINTSTATUS::WARN,
                    format!("[Warning]: Passwords do not match. Key update cancelled."),
                );
                return;
            }

            let (nonce_bytes, encrypted_bytes) = match encrypt(key, &new_value, master_password) {
                Some(pair) => pair,
                None => {
                    print_message(PRINTSTATUS::ERROR, format!("Key derivation failed."));
                    return;
                }
            };

            let record = EncryptedRecord {
                nonce: Base64::encode_string(&nonce_bytes),
                encrypted_value: Base64::encode_string(&encrypted_bytes),
            };

            clear_screen();
            if let Ok(serialized) = serde_json::to_string_pretty(&record) {
                if write(key_file_path, serialized).is_ok() {
                    print_message(PRINTSTATUS::SUCCESS, format!("Updated '{key}'."));
                    return;
                }
            }
            print_message(PRINTSTATUS::ERROR, format!("Could not update the entry."));
        }
        2 => {
            // Copy
            clear_screen();
            if let Ok(contents) = read_to_string(&key_file_path) {
                if let Ok(record) = serde_json::from_str::<EncryptedRecord>(&contents) {
                    let nonce_bytes = Base64::decode_vec(&record.nonce).ok();
                    let encrypted_bytes = Base64::decode_vec(&record.encrypted_value).ok();

                    if let (Some(n_bytes), Some(e_bytes)) = (nonce_bytes, encrypted_bytes) {
                        if let Some(decrypted) = decrypt(key, &e_bytes, &n_bytes, master_password) {
                            copy_to_clipboard(&decrypted);
                            return;
                        }
                    }
                }
            }
            print_message(
                PRINTSTATUS::ERROR,
                format!(
                    "Decryption failed. Possible causes: Incorrect master password or data corruption."
                ),
            );
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
                clear_screen();
                if remove_file(key_file_path).is_ok() {
                    print_message(PRINTSTATUS::SUCCESS, format!("Deleted '{}'.", key));
                } else {
                    print_message(PRINTSTATUS::ERROR, format!("Failed to delete entry file."));
                }
            }
        }
        _ => {}
    }
}

pub fn print_message(status: PRINTSTATUS, msg: String) {
    match status {
        PRINTSTATUS::ERROR => {
            eprintln!("{}", format!("[ERROR]: {}", msg).red());
        }
        PRINTSTATUS::WARN => {
            println!("{}", format!("[WARN]: {}", msg).yellow());
        }
        PRINTSTATUS::SUCCESS => {
            println!("{}", format!("[SUCCESS]: {}", msg).green());
        }
        PRINTSTATUS::INFO => {
            println!("{}", format!("{}", msg).cyan());
        }
    }
}
