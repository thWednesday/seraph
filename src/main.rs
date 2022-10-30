// #![allow(non_snake_case)]
#![allow(unused_variables)]

mod hash;

use allwords::Alphabet;
use clap::{value_parser, Arg, Command};
use hash::{compute, hash_from, identify_hash, valid_hash};
use text2art::{BasicFonts, Font, Printer};

// #[tokio::main]
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
                .default_value("alphabet")
                .value_parser(value_parser!(String))
                .requires("bruteforce")
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

    let raw_hash = matches.get_one::<String>("hash").unwrap();
    let hash: &[u8] = &valid_hash(raw_hash.as_bytes());
    let hash_type = hash_from(matches.get_one::<String>("type").unwrap().to_uppercase());
    let mut alphabet_raw = match matches
        .get_one::<String>("preset")
        .unwrap()
        .to_lowercase()
        .as_str()
    {
        "lw" | "low" | "lowercase" => "abcdefghijklmnopqrstuvwxyz ",
        "up" | "uppercase" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ ",
        "n" | "nr" | "numbers" => "0123456789 ",
        "a" | "all" => " 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,./;'[]<>?:\"{}-=!@#$%^&*() ",
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
        alphabet_raw = &alphabet_raw[0..alphabet_raw.len() - 1];
    }

    let alphabet = Alphabet::from_chars_in_str(alphabet_raw).unwrap();

    let verbose: bool = matches.get_flag("verbose");
    macro_rules! debug {
        ($string: expr) => {
            // match VERBOSE {
            //     1 => println!("[{}] {}", env!("CARGO_PKG_NAME"), $string),
            //     0 => (),
            //     _ => (),
            // }

            println!("[{}] {}", env!("CARGO_PKG_NAME"), $string)
        };

        ($string: expr, $verbosity: expr) => {
            match $verbosity {
                true => println!("[{}] { }", env!("CARGO_PKG_NAME"), $string),
                false => (),
            }
        };
    }

    debug!(format!("ALPHABET: {}", alphabet_raw));

    if hash.len() > 1 {
        let hash_string = hash_type.to_string();
        debug!(format!("{} {}", raw_hash, hash_string));

        if hash_string == "NULL" {
            debug!(
                format!(
                    "GUESSED {}",
                    identify_hash(hash.len().try_into().expect("Error getting hash length"))
                        .to_string()
                ),
                true
            )
        }
    } else {
        debug!("Not a valid hash")
    }

    if matches.get_flag("bruteforce") {
        let mut found: bool = false;

        for combination in alphabet.all_words(Some(*matches.get_one::<usize>("length").unwrap())) {
            let hashed = compute(combination.as_str());

            debug!(
                format!("STRING / HASH: {} -> {}", combination, hashed),
                verbose
            );

            // println!("{:#?} {:#?}", hash, hashed.as_bytes());
            // break;
            if hash.eq(&valid_hash(hashed.as_bytes())) {
                debug!(format!("STRING FOUND: {} -> {}", combination, hashed));
                found = true;

                break;
            }
        }

        if !found {
            debug!("String couldn't be bruteforced")
        }
    }
}
