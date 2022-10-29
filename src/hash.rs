/*
    https://docs.rs/sha3
    https://docs.rs/md5
*/

use hex_literal::hex;
use regex::Regex;

pub enum Hash {
    MD5,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    NULL,
}

impl Hash {
    pub fn to_string(self) -> String {
        match self {
            Hash::MD5 => "MD5".to_string(),
            Hash::SHA224 => "SHA224".to_string(),
            Hash::SHA256 => "SHA256".to_string(),
            Hash::SHA384 => "SHA384".to_string(),
            Hash::SHA512 => "SHA512".to_string(),
            Hash::NULL => "NULL".to_string(),
        }
    }
}

pub fn hashFromString(hashType: String) -> Hash {
    match hashType.as_str() {
        "MD5" => Hash::MD5,
        "SHA224" => Hash::SHA224,
        "SHA256" => Hash::SHA256,
        "SHA384" => Hash::SHA384,
        "SHA512" => Hash::SHA512,
        _ => Hash::NULL,
    }
}

pub fn hashType(hashLength: i32) -> Hash {
    match hashLength {
        32 => Hash::MD5,
        56 => Hash::SHA224,
        64 => Hash::SHA256,
        96 => Hash::SHA384,
        128 => Hash::SHA512,
        _ => Hash::NULL,
    }
}

pub fn validHash(hash: String) -> bool {
    match hash.len() {
        32 | 56 | 64 | 96 | 128 => {
            let regex =
                Regex::new(format!("(?i)([a-f\\d]{})", format!("{{{}}}", hash.len())).as_str())
                    .unwrap();

            let result = regex.captures_iter(hash.as_str());
            let results = result.count();

            // for mat in result {
            //     println!("{:?}", mat);
            // }

            return results > 0;
        }

        _ => return false,
    }
}

pub fn hash(seekanddestroy: &str) -> String {
    return format!("{:x}", md5::compute(seekanddestroy));
}
