#![allow(non_snake_case)]
#![allow(unused_variables)]

mod hash;

use clap::{value_parser, Arg, Command};
use hash::{hash, hashFromString, hashType, validHash};
use text2art::{BasicFonts, Font, Printer};

// #[tokio::main]
fn main() {
    let LOGO: String = Printer::with_font(Font::from_basic(BasicFonts::Bell).unwrap())
        .render_text(format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")).as_str())
        .unwrap()
        .to_string();

    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .before_help(LOGO.as_str())
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
                .default_value("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
                .value_parser(value_parser!(String))
                .help("Bruteforce alphabet"),
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
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Make program more verbose"),
        )
        .get_matches();
    let HASH: &str = matches.get_one::<String>("hash").unwrap();
    let HASH_TYPE = hashFromString(matches.get_one::<String>("type").unwrap().to_uppercase());
    let ALPHABET = matches.get_one::<String>("alphabet").unwrap();

    let VERBOSE: bool = matches.get_flag("verbose");

    macro_rules! debug {
        ($string: expr) => {
            match VERBOSE {
                true => println!("[{}] {}", env!("CARGO_PKG_NAME"), $string),
                false => (),
            }
        };

        ($string: expr, $verbosity: expr) => {
            match $verbosity {
                true => println!("[{}] { }", env!("CARGO_PKG_NAME"), $string),
                false => (),
            }
        };
    }

    debug!(format!("ALPHABET: {}", ALPHABET));

    if validHash(HASH.to_string()) {
        let hashString = HASH_TYPE.to_string();
        debug!(format!("{} {}", HASH, hashString), true);

        if hashString == "NULL" {
            debug!(
                format!(
                    "GUESSED {}",
                    hashType(HASH.len().try_into().expect("Error getting hash length")).to_string()
                ),
                true
            )
        }
    } else {
        debug!("Not a valid hash")
    }

    let ALPH_VEC = ALPHABET.split("");

    let mut hashString = String::from("");
    // 'dehash: loop {
    //     let mut lastLetter = "";
    //     for letter in ALPH_VEC.clone() {
    //         if hash(&temp) == HASH {
    //             debug!(format!("{}", letter));
    //             break 'dehash;
    //         }

    //         debug!(format!("{}", hashString));
    //         lastLetter = letter;
    //     }

    //     hashString.push_str(lastLetter);
    // }
    'dehash: for i in 1..2 {
        for x in ALPH_VEC.clone() {
            for y in ALPH_VEC.clone() {
                hashString = format!("{}{}", x, y);

                if hash(&hashString) == HASH {
                    debug!(format!("HASH FOUND: {}", hashString));
                    break 'dehash;
                }
            }
        }
    }
}
