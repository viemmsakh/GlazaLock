use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use base64ct::{Base64, Encoding};
use dialoguer::{FuzzySelect, Input, Password, theme::ColorfulTheme};
use rand::Rng;
use std::fs::{read_dir, read_to_string, write};

// Import Custom Modules and Enums
use crate::helper;
use crate::structs::{AppConfig, EncryptedRecord, PRINTSTATUS};

pub fn generate_password(
    length: usize,
    uppercase: bool,
    numbers: bool,
    symbols: bool,
    word: bool,
    copy: bool,
) {
    if length < 8 {
        helper::print_message(
            PRINTSTATUS::ERROR,
            format!("Password requested less than 8 characters.... Not secure, giving up."),
        );
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
        helper::print_message(PRINTSTATUS::SUCCESS, format!("{}", password));
    }
}

pub fn reset_master_password(master_password: &str) {
    let theme = ColorfulTheme::default();
    let argon2 = Argon2::default();
    helper::print_message(PRINTSTATUS::INFO, format!("--- Reset Master Password ---"));

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
        helper::print_message(
            PRINTSTATUS::ERROR,
            format!("New password cannot be identical to your current password."),
        );
        return;
    }

    if new_master_password != confirm_master_password {
        helper::print_message(
            PRINTSTATUS::ERROR,
            format!("Passwords do not match. Reset aborted."),
        );
        return;
    }

    helper::print_message(
        PRINTSTATUS::SUCCESS,
        format!("Re-encrypting database vault secrets... Do not close the application."),
    );

    let keys_dir = match helper::get_keys_dir() {
        Ok(p) => p,
        Err(_) => return,
    };

    let entries = match read_dir(&keys_dir) {
        Ok(d) => d,
        Err(e) => {
            helper::print_message(
                PRINTSTATUS::ERROR,
                format!("Failed to scan the flatfile key workspace directory: {}", e),
            );
            return;
        }
    };

    // Iterate over every flatfile key entry inside ~/.glock/keys/ and migrate them one-by-one
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let key_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };

        if let Ok(contents) = read_to_string(&path) {
            if let Ok(record) = serde_json::from_str::<EncryptedRecord>(&contents) {
                // Decode from textual base64 back into raw bytes for cryptography
                let nonce_bytes = Base64::decode_vec(&record.nonce).ok();
                let encrypted_bytes = Base64::decode_vec(&record.encrypted_value).ok();

                if let (Some(n_bytes), Some(e_bytes)) = (nonce_bytes, encrypted_bytes) {
                    let decrypted_password = match helper::decrypt(
                        &key_name,
                        &e_bytes,
                        &n_bytes,
                        master_password,
                    ) {
                        Some(decrypted) => decrypted,
                        None => {
                            helper::print_message(
                                PRINTSTATUS::ERROR,
                                format!(
                                    "Decryption failed for key '{}'. Corrupted block or cipher mismatch.",
                                    key_name
                                ),
                            );
                            return;
                        }
                    };

                    // Re-encrypt the secret data under the newly chosen master password
                    let (new_nonce, encrypted_password) =
                        match helper::encrypt(&key_name, &decrypted_password, &new_master_password)
                        {
                            Some(pair) => pair,
                            None => return,
                        };

                    // Serialize raw binary blocks back into safe, textual base64 JSON records
                    let updated_record = EncryptedRecord {
                        nonce: Base64::encode_string(&new_nonce),
                        encrypted_value: Base64::encode_string(&encrypted_password),
                    };

                    if let Ok(serialized) = serde_json::to_string_pretty(&updated_record) {
                        if write(&path, serialized).is_err() {
                            helper::print_message(
                                PRINTSTATUS::ERROR,
                                format!(
                                    "Failed to save re-encrypted record flatfile block for '{}'. Aborting.",
                                    key_name
                                ),
                            );
                            return;
                        }
                    }
                }
            }
        }
    }

    // Generate a fresh signature hash for the new system configuration master entry
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

    if let Ok(config_path) = helper::get_config_path() {
        let new_config = AppConfig { password_hash };
        if let Ok(serialized) = serde_json::to_string_pretty(&new_config) {
            if write(config_path, serialized).is_ok() {
                helper::print_message(
                    PRINTSTATUS::SUCCESS,
                    format!("Master password updated successfully."),
                );
                return;
            }
        }
    }

    helper::print_message(
        PRINTSTATUS::ERROR,
        format!("Failed to finalize system configuration hash values cleanly to disk."),
    );
}

pub fn run_interactive(master_password: &str) {
    let theme = ColorfulTheme::default();
    loop {
        let keys = helper::get_all_keys();
        let mut options = vec!["[Create New Key]".to_string()];
        options.extend(keys.clone());
        options.push("[Exit]".to_string());

        helper::print_message(PRINTSTATUS::INFO, format!("\n--- Interactive Mode ---"));
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
            // Create New Key Flatfile Entry
            helper::create_key_prompt(master_password);
        } else if selection == options.len() - 1 {
            break;
        } else {
            if let Some(selected_key) = keys.get(selection - 1) {
                let selected_key = selected_key.trim();
                // Manage Existing Flatfile Key Lifecycle Actions
                helper::manage_existing_key(selected_key, master_password);
            }
        }
    }
}

pub fn run_read(key: Option<String>, master_password: &str, copy: bool) {
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

    let mut key_path = match helper::get_keys_dir() {
        Ok(p) => p,
        Err(_) => return,
    };
    key_path.push(&key);

    if !key_path.exists() {
        helper::print_message(
            PRINTSTATUS::ERROR,
            format!(
                "Key '{}' not found in flatfile database storage environment.",
                key
            ),
        );
        return;
    }

    if let Ok(contents) = read_to_string(key_path) {
        if let Ok(record) = serde_json::from_str::<EncryptedRecord>(&contents) {
            // Convert string block tokens into bytes for hardware crypto computation
            let nonce_bytes = Base64::decode_vec(&record.nonce).ok();
            let encrypted_bytes = Base64::decode_vec(&record.encrypted_value).ok();

            if let (Some(n_bytes), Some(e_bytes)) = (nonce_bytes, encrypted_bytes) {
                match helper::decrypt(&key, &e_bytes, &n_bytes, master_password) {
                    Some(decrypted) => {
                        if copy {
                            helper::copy_to_clipboard(&decrypted);
                        } else {
                            helper::print_message(
                                PRINTSTATUS::SUCCESS,
                                format!("{}: {}", key, decrypted),
                            );
                        }
                    }
                    None => helper::print_message(
                        PRINTSTATUS::ERROR,
                        format!(
                            "Decryption failed. Corrupted block data or cipher initialization mismatch."
                        ),
                    ),
                }
                return;
            }
        }
    }

    helper::print_message(
        PRINTSTATUS::ERROR,
        format!(
            "Failed to successfully parse the encrypted text block for key '{}'.",
            key
        ),
    );
}
