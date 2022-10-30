use std::process::exit;

pub fn error(message: &str) {
    println!("[{}] [err] {}", env!("CARGO_PKG_NAME"), message);
    exit(1);
}
