use openssl::symm::{Cipher, decrypt};
use std::{fs, io::{self, Write}};
use log::{info, error};
use std::fs::File;


const SECRET_KEY: &[u8] = b"dasfsdf4354#@#^%fsdfs2354543dasf"; 

fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = &encrypted_data[0..16]; 
    let data = &encrypted_data[16..]; 
    let cipher = Cipher::aes_256_cbc();
    let decrypted_data = decrypt(cipher, key, Some(iv), data).unwrap();
    decrypted_data
}

fn main() -> io::Result<()> {
    env_logger::init();

    let shared_memory_path = "/dev/shm/encrypted_data2.bin";
    let encrypted_data = fs::read(shared_memory_path).expect("Unable to read encrypted data from shared memory");

    let decrypted_data = decrypt_data(&encrypted_data, SECRET_KEY);
    info!("Data decrypted successfully.");

    let output_dir = "test_data";
    fs::create_dir_all(output_dir)?;

    let output_path = format!("{}/DecryptedInput2.jpg", output_dir);
    let mut file = File::create(output_path)?;
    file.write_all(&decrypted_data)?;

    info!("Decrypted data saved to file in directory: {}", output_dir);

    Ok(())
}
