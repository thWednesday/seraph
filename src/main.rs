// #![allow(non_snake_case)]
// #![allow(unused_variables)]

mod hash;
mod util;

use allwords::Alphabet;
use clap::{value_parser, Arg, Command};
use hash::{Hash, HashType, Hasher};
use text2art::{BasicFonts, Font, Printer};

fn main() {
    let logo: String = Printer::with_font(Font::from_basic(BasicFonts::Bell).unwrap())
        .render_text(format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")).as_str())
        .unwrap()
        .to_string();

    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .before_help(logo.as_str())
        // .about("hash bruteforce program")
        .help_template("{before-help}{about}\n{usage-heading} {usage}\n\n{all-args}")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .required(true)
                .takes_value(true)
                .value_parser(value_parser!(String))
                .help("Hash to bruteforce"),
        )
        .arg(
            Arg::new("alphabet")
                .short('a')
                .long("alphabet")
                .takes_value(true)
                .default_value("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ")
                .value_parser(value_parser!(String))
                .requires("bruteforce")
                .help("Bruteforce alphabet")
                .overrides_with("preset"),
        )
        .arg(
            Arg::new("preset")
                .short('p')
                .long("preset")
                .takes_value(true)
                .default_value("none")
                .value_parser(value_parser!(String))
                .requires("bruteforce")
                .possible_values([
                    "none",
                    "lw",
                    "low",
                    "lowercase",
                    "up",
                    "uppercase",
                    "nr",
                    "numbers",
                    "all",
                ])
                .help("Alphabet preset")
                .conflicts_with("alphabet"),
        )
        .arg(
            Arg::new("type")
                .short('t')
                .long("type")
                .default_value("GUESS")
                .takes_value(true)
                .possible_values(["GUESS", "MD5", "SHA224", "SHA256", "SHA384", "SHA512"])
                .ignore_case(true)
                .help("Hash type"),
        )
        .arg(
            Arg::new("bruteforce")
                .short('b')
                .long("bruteforce")
                .action(clap::ArgAction::SetTrue)
                .help("Enable bruteforcing"),
        )
        .arg(
            Arg::new("nospace")
                .short('w')
                .long("nospace")
                .action(clap::ArgAction::SetTrue)
                .requires("bruteforce")
                .help("Remove spaces from bruteforce alphabet"),
        )
        .arg(
            Arg::new("length")
                .short('l')
                .long("length")
                .default_value("99")
                .value_parser(value_parser!(usize))
                .requires("bruteforce")
                .help("Set the maximum possible length of the unhashed string"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Make program more verbose"),
        )
        .get_matches();

    let raw_type = HashType::hash_from(matches.get_one::<String>("hash").unwrap().to_string());
    let mut hasher: Hash = Hash {
        hash_type: raw_type,
        hasher: Hasher::Null,
    };

    let hash: &[u8] = &hash::Hash::hex(
        &matches
            .get_one::<String>("hash")
            .unwrap()
            .to_owned()
            .into_bytes(),
    );

    let length = matches.get_one::<usize>("length").unwrap();
    let mut raw_alphabet = match matches
        .get_one::<String>("preset")
        .unwrap()
        .to_lowercase()
        .as_str()
    {
        "lw" | "low" | "lowercase" => "abcdefghijklmnopqrstuvwxyz ",
        "up" | "uppercase" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ ",
        "nr" | "numbers" => "0123456789 ",
        "all" => " 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]<>?:\"{}-=!@#$%^&*() ",
        _ => matches.get_one::<String>("alphabet").unwrap(),
    };

    if matches.get_flag("nospace")
        && !matches
            .value_source("alphabet")
            .unwrap()
            .eq(&clap::ValueSource::CommandLine)
    {
        // https://stackoverflow.com/a/65976485
        // quite the hack
        raw_alphabet = &raw_alphabet[0..raw_alphabet.len() - 1];
    }

    let alphabet = Alphabet::from_chars_in_str(raw_alphabet).unwrap();

    let verbose: bool = matches.get_flag("verbose");
    macro_rules! debug {
        ($string: expr) => {
            println!("[{}] {}", env!("CARGO_PKG_NAME"), $string)
        };

        ($string: expr, $verbosity: expr) => {
            match $verbosity {
                true => println!("[{}] { }", env!("CARGO_PKG_NAME"), $string),
                false => (),
            }
        };
    }

    let raw_hash = matches.get_one::<String>("hash").unwrap();

    debug!(format!("ALPHABET: {}", raw_alphabet));
    debug!(format!("{}", raw_hash));

    if hasher.hash_type.to_string().eq("NULL") {
        hasher.hash_type = HashType::identify_hash(
            raw_hash
                .len()
                .try_into()
                .expect("Error getting hash length"),
        );

        debug!(format!("GUESSED {}", hasher.hash_type.to_string()))
    }

    hasher.hasher();

    if matches.get_flag("bruteforce") {
        let mut found: bool = false;

        for combination in alphabet.all_words(Some(*length)) {
            let hashed = hasher.compute(combination.as_str());
            let raw = std::str::from_utf8(hashed.as_slice()).unwrap();

            debug!(
                format!("STRING / HASH: {} -> {}", combination, raw),
                verbose
            );

            if hash.eq(&Hash::hex(&hashed)) {
                debug!(format!("STRING FOUND: {} -> {}", combination, raw));
                found = true;

                break;
            }
        }

        if !found {
            util::error("String couldn't be bruteforced");
        }
    }
}
