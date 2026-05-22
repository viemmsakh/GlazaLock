use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, name = "GlazaLock", about = "A secure local key-value store for passwords.", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a secure random password with customizable options
    Generate {
        #[arg(
            short,
            long,
            default_value_t = 16,
            help = "Length of the generated password"
        )]
        length: usize,
        #[arg(
            short,
            long,
            help = "Include uppercase letters in the generated password"
        )]
        uppercase: bool,
        #[arg(short, long, help = "Include numbers in the generated password")]
        numbers: bool,
        #[arg(short, long, help = "Include symbols in the generated password")]
        symbols: bool,
        #[arg(short, long, help = "Include words in the generated password")]
        word: bool,
        #[arg(
            short,
            long,
            help = "Copy generated value to clipboard instead of printing to console"
        )]
        copy: bool,
    },
    /// Enter interactive management mode
    Interactive,
    /// Read and decrypt a specific key
    Read {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(
            short,
            long,
            help = "Copy decrypted value to clipboard instead of printing to console"
        )]
        copy: bool,
    },
    /// Reset master password, must know existing master password.
    Reset,
}
