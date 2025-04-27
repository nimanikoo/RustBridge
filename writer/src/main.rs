use openssl::symm::{Cipher, encrypt};
use std::{fs, io::{self, Write}};
use log::{info, error};
use std::fs::File;
use rand::random;

const SECRET_KEY: &[u8] = b"dasfsdf4354#@#^%fsdfs2354543dasf"; 

fn encrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = random::<[u8; 16]>();
    let cipher = Cipher::aes_256_cbc();

    match encrypt(cipher, key, Some(&iv), data) {
        Ok(encrypted_data) => {
            let mut result = iv.to_vec(); 
            result.extend_from_slice(&encrypted_data);
            result
        },
        Err(e) => {
            error!("Encryption failed: {}", e);
            panic!("Encryption failed");
        }
    }
}

fn main() -> io::Result<()> {
    env_logger::init();

    let file_path = "test_data/input.jpg";
    let data = fs::read(file_path).expect("Unable to read file"); 

    let encrypted_data = encrypt_data(&data, SECRET_KEY);
    info!("Data encrypted successfully.");

    let encrypted_file_path = "/dev/shm/encrypted_data2.bin"; 
    let mut file = File::create(encrypted_file_path)
        .expect("Unable to create encrypted file");

    file.write_all(&encrypted_data)
        .expect("Failed to write encrypted data to file");

    info!("Encrypted data written to {}", encrypted_file_path);

    Ok(())
}
