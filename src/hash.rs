use crate::util::error;
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha2::{Sha224, Sha256, Sha384, Sha512};
use hex::decode;

pub enum HashType {
    MD5,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    NULL,
}

pub enum Hasher {
    Md5,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Null,
}

pub struct Hash {
    pub hash_type: HashType,
    pub hasher: Hasher,
}

impl HashType {
    pub fn hash_from(hash_type: String) -> HashType {
        return match hash_type.as_str() {
            "MD5" => HashType::MD5,
            "SHA224" => HashType::SHA224,
            "SHA256" => HashType::SHA256,
            "SHA384" => HashType::SHA384,
            "SHA512" => HashType::SHA512,
            _ => HashType::NULL,
        };
    }

    pub fn identify_hash(hash_length: i32) -> HashType {
        return match hash_length {
            32 => HashType::MD5,
            56 => HashType::SHA224,
            64 => HashType::SHA256,
            96 => HashType::SHA384,
            128 => HashType::SHA512,
            _ => HashType::NULL,
        };
    }

    pub fn to_string(&self) -> String {
        match self {
            HashType::MD5 => "MD5".to_string(),
            HashType::SHA224 => "SHA224".to_string(),
            HashType::SHA256 => "SHA256".to_string(),
            HashType::SHA384 => "SHA384".to_string(),
            HashType::SHA512 => "SHA512".to_string(),
            HashType::NULL => "NULL".to_string(),
        }
    }
}

impl Hash {
    pub fn compute(&mut self, uncomputed: &str) -> Vec<u8> {
        return match self.hasher {
            Hasher::Md5 => {
                let mut hasher = Md5::new();
                hasher.input(uncomputed.as_bytes());

                hasher.result_str().into_bytes()
            }

            Hasher::Sha224 => {
                let mut hasher = Sha224::new();
                hasher.input(uncomputed.as_bytes());

                hasher.result_str().into_bytes()
            }

            Hasher::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.input(uncomputed.as_bytes());

                hasher.result_str().into_bytes()
            }

            Hasher::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.input(uncomputed.as_bytes());

                hasher.result_str().into_bytes()
            }

            Hasher::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.input(uncomputed.as_bytes());

                hasher.result_str().into_bytes()
            }

            Hasher::Null => "".as_bytes().to_vec(),
            // _ => vec![],
        };
    }

    pub fn hasher(&mut self) {
        self.hasher = match self.hash_type {
            HashType::MD5 => Hasher::Md5,
            HashType::SHA224 => Hasher::Sha224,
            HashType::SHA256 => Hasher::Sha256,
            HashType::SHA384 => Hasher::Sha384,
            HashType::SHA512 => Hasher::Sha512,
            HashType::NULL => Hasher::Null,
        }
    }

    pub fn hex(hash: &Vec<u8>) -> Vec<u8> {
        match hash.len() {
            32 | 56 | 64 | 96 | 128 => {
                // thanks @cyyynthia for the hex decode idea
                return decode(&hash).unwrap();
            }

            _ => {
                error("Not a valid hash");
                vec![]
            }
        }
    }
}
