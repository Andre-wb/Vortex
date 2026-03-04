use pyo3::{
    prelude::*,
    types::PyBytes,
};
use vortex_chat::{hash_message, generate_key, encrypt_message, decrypt_message, ChatStats};
#[cfg(test)]
mod tests {
    use super::*;

    ///  Check key limit
    #[test]
    fn test_generating() -> PyResult<()> {
        let key = generate_key()?;
        assert_eq!(key.len(), 32, "Key should be 32 bytes");
        Ok(())
    }

    /// Chack hash limit
    #[test]
    fn test_hashing() -> PyResult<()> {
        let message = Vec::new();
        let hash = hash_message(message)?;
        assert_eq!(hash.len(), 32, "hash should be 32 bytes");

        Ok(())
    }

    /// Message encrypt and decrypt
    #[test]
    fn test_message_encrypting() -> PyResult<()> {
        let message = "message";
        let key = generate_key()?;
        let encrypted = encrypt_message(message, key.clone())?;
        assert!(encrypted.len() > message.len(), "Encrypted data is not larger than original");

        let decrypted = decrypt_message(encrypted, key)?;
        assert_eq!(decrypted, message, "Decrypted message do not match original");

        Ok(())
    }

    #[test]
    fn test_tampering_detection() -> PyResult<()> {
        let key = generate_key()?;
        let message = "message";
        let encrypted = encrypt_message(&message, key.clone())?;

        let tampered = Vec::new();
        let result = decrypt_message(tampered, key);
        assert!(result.is_err(), "Tampered nonce did not caused the decryption failure");

        let wrong_key = generate_key()?;
        let result = decrypt_message(encrypted, wrong_key);
        assert!(result.is_err(), "Wrong key did not failed decryption");

        Ok(())
    }

    #[test]
    fn test_determinism() -> PyResult<()> {

        let key = generate_key()?;
        let message = "message";

        // Same messages should have different encrypting
        let encrypted1 = encrypt_message(message, key.clone())?;
        let encrypted2 = encrypt_message(message, key.clone())?;

        assert_ne!(encrypted1, encrypted2, "Encryptions did not had different crypt");

        // Same messages should have the same decrypting
        let decrypted1 = decrypt_message(encrypted1, key.clone())?;
        let decrypted2 = decrypt_message(encrypted2, key)?;

        assert_eq!(decrypted1.as_bytes(), decrypted2.as_bytes());
        assert_eq!(decrypted1.as_bytes(), b"message");
        assert_ne!(decrypted1.as_bytes(), b"wrong message");

        Ok(())

    }

    /// Chat statistics
    #[test]
    fn test_chat_stats() {
        let mut stats = ChatStats::new();
        assert_eq!(stats.get_stats(), "📊 Messages: 0, processed: 0 KB");

        stats.add_message(1024);
        assert_eq!(stats.get_stats(), "📊 Messages: 1, processed: 1 KB");

        stats.add_message(2048);
        assert_eq!(stats.get_stats(), "📊 Messages: 2, processed: 3 KB");
    }


    // /// Performance benchmark test
    // #[test]
    // fn test_performance() -> PyResult<()> {
    //     pyo3::prepare_freethreaded_python();
    // 
    //     Python::with_gil(|py| {
    //         let key = generate_key(py)?;
    //         let message_sizes = [64, 1024, 16384, 65536];
    //         let iterations = 100;
    // 
    //         println!("\n=== Performance Benchmarks ===");
    // 
    //         for &size in &message_sizes {
    //             let data = vec![0xAB; size];
    //             let message = PyBytes::new(py, &data);
    // 
    //             // Encryption benchmark
    //             let start = Instant::now();
    //             let mut encrypted_vec = Vec::with_capacity(iterations);
    //             for _ in 0..iterations {
    //                 let encrypted = encrypt_message(py, &message.as_borrowed(), &key.as_borrowed())?;
    //                 encrypted_vec.push(encrypted.as_bytes().to_vec());
    //             }
    //             let encrypt_duration = start.elapsed();
    // 
    //             // Decryption benchmark
    //             let start = Instant::now();
    //             for encrypted_data in &encrypted_vec {
    //                 let encrypted_bytes = PyBytes::new(py, encrypted_data);
    //                 let _ = decrypt_message(py, &encrypted_bytes.as_borrowed(), &key.as_borrowed())?;
    //             }
    //             let decrypt_duration = start.elapsed();
    // 
    //             let encrypt_throughput = (size * iterations) as f64 / encrypt_duration.as_secs_f64() / 1_000_000.0;
    //             let decrypt_throughput = (size * iterations) as f64 / decrypt_duration.as_secs_f64() / 1_000_000.0;
    // 
    //             println!("Size {} bytes:", size);
    //             println!("  Encrypt: {:?} for {} ops ({:.2} MB/s)",
    //                      encrypt_duration, iterations, encrypt_throughput);
    //             println!("  Decrypt: {:?} for {} ops ({:.2} MB/s)",
    //                      decrypt_duration, iterations, decrypt_throughput);
    //         }
    // 
    //         Ok(())
    //     })
    // }
    // 
    // /// Concurrent usage test (if threading is supported)
    // #[test]
    // fn test_concurrent_usage() -> PyResult<()> {
    //     pyo3::prepare_freethreaded_python();
    // 
    //     use std::thread;
    // 
    //     let handles: Vec<_> = (0..4).map(|i| {
    //         thread::spawn(move || {
    //             Python::with_gil(|py| -> PyResult<()> {
    //                 let key = generate_key(py)?;
    //                 let message = PyBytes::new(py, format!("Thread {} message", i).as_bytes());
    // 
    //                 for _ in 0..10 {
    //                     let encrypted = encrypt_message(py, &message.as_borrowed(), &key.as_borrowed())?;
    //                     let decrypted = decrypt_message(py, &encrypted.as_borrowed(), &key.as_borrowed())?;
    //                     assert_eq!(decrypted.as_bytes(), message.as_bytes());
    //                 }
    // 
    //                 Ok(())
    //             }).unwrap();
    //         })
    //     }).collect();
    // 
    //     for handle in handles {
    //         handle.join().unwrap();
    //     }
    // 
    //     Ok(())
    // }
}