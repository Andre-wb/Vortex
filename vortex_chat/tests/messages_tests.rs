use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vortex_chat::{hash_message, generate_key, encrypt_message, decrypt_message, ChatStats};
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic functionality tests
    #[test]
    fn test_basic_functionality() -> PyResult<()> {
        pyo3::prepare_freethreaded_python();

        Python::with_gil(|py| {
            // Test generate_key
            let key = generate_key(py)?;
            assert_eq!(key.as_bytes().len(), 32, "Key should be 32 bytes");

            // Test hash_message
            let test_message = PyBytes::new(py, b"Hello, World!");
            let hash = hash_message(py, &test_message.as_borrowed())?;
            assert_eq!(hash.as_bytes().len(), 32, "BLAKE3 hash should be 32 bytes");

            // Test encryption/decryption
            let original = b"Secret message for testing";
            let message_bytes = PyBytes::new(py, original);

            let encrypted = encrypt_message(py, &message_bytes.as_borrowed(), &key.as_borrowed())?;
            assert!(encrypted.as_bytes().len() > original.len(), "Encrypted data should be larger than original");

            let decrypted = decrypt_message(py, &encrypted.as_borrowed(), &key.as_borrowed())?;
            assert_eq!(decrypted.as_bytes(), original, "Decrypted message should match original");

            Ok(())
        })
    }

    /// Tampering and integrity tests
    #[test]
    fn test_tampering_detection() -> PyResult<()> {
        pyo3::prepare_freethreaded_python();

        Python::with_gil(|py| {
            let key = generate_key(py)?;
            let message = PyBytes::new(py, b"Sensitive data");
            let encrypted = encrypt_message(py, &message.as_borrowed(), &key.as_borrowed())?;

            let mut tampered_data = encrypted.as_bytes().to_vec();

            // Tamper with nonce
            if !tampered_data.is_empty() {
                tampered_data[0] ^= 0x01;
            }
            let tampered = PyBytes::new(py, &tampered_data);
            let result = decrypt_message(py, &tampered.as_borrowed(), &key.as_borrowed());
            assert!(result.is_err(), "Tampered nonce should cause decryption failure");

            // Tamper with ciphertext
            let mut encrypted_vec = encrypted.as_bytes().to_vec();
            if encrypted_vec.len() > 13 {
                encrypted_vec[13] ^= 0x01; // Flip a bit in ciphertext
            }
            let tampered = PyBytes::new(py, &encrypted_vec);
            let result = decrypt_message(py, &tampered.as_borrowed(), &key.as_borrowed());
            assert!(result.is_err(), "Tampered ciphertext should cause decryption failure");

            // Wrong key test
            let wrong_key = generate_key(py)?;
            let result = decrypt_message(py, &encrypted.as_borrowed(), &wrong_key.as_borrowed());
            assert!(result.is_err(), "Wrong key should fail decryption");

            Ok(())
        })
    }

    /// ChatStats tests
    #[test]
    fn test_chat_stats() {
        pyo3::prepare_freethreaded_python();

        Python::with_gil(|_py| {
            let mut stats = ChatStats::new();
            assert_eq!(stats.get_stats(), "📊 Messages: 0, processed: 0 KB");

            stats.add_message(1024);
            assert_eq!(stats.get_stats(), "📊 Messages: 1, processed: 1 KB");

            stats.add_message(2048);
            assert_eq!(stats.get_stats(), "📊 Messages: 2, processed: 3 KB");
        })
    }

    /// Determinism and consistency tests
    #[test]
    fn test_determinism() -> PyResult<()> {
        pyo3::prepare_freethreaded_python();

        Python::with_gil(|py| {
            let key = generate_key(py)?;
            let message = PyBytes::new(py, b"Test message");

            // Same message encrypted twice should produce different results (due to random nonce)
            let encrypted1 = encrypt_message(py, &message.as_borrowed(), &key.as_borrowed())?;
            let encrypted2 = encrypt_message(py, &message.as_borrowed(), &key.as_borrowed())?;

            assert_ne!(encrypted1.as_bytes(), encrypted2.as_bytes(),
                       "Encryptions should be different due to random nonce");

            // But decryption should always work
            let decrypted1 = decrypt_message(py, &encrypted1.as_borrowed(), &key.as_borrowed())?;
            let decrypted2 = decrypt_message(py, &encrypted2.as_borrowed(), &key.as_borrowed())?;

            assert_eq!(decrypted1.as_bytes(), decrypted2.as_bytes());
            assert_eq!(decrypted1.as_bytes(), b"Test message");

            Ok(())
        })
    }

    /// Performance benchmark test
    #[test]
    fn test_performance() -> PyResult<()> {
        pyo3::prepare_freethreaded_python();

        Python::with_gil(|py| {
            let key = generate_key(py)?;
            let message_sizes = [64, 1024, 16384, 65536];
            let iterations = 100;

            println!("\n=== Performance Benchmarks ===");

            for &size in &message_sizes {
                let data = vec![0xAB; size];
                let message = PyBytes::new(py, &data);

                // Encryption benchmark
                let start = Instant::now();
                let mut encrypted_vec = Vec::with_capacity(iterations);
                for _ in 0..iterations {
                    let encrypted = encrypt_message(py, &message.as_borrowed(), &key.as_borrowed())?;
                    encrypted_vec.push(encrypted.as_bytes().to_vec());
                }
                let encrypt_duration = start.elapsed();

                // Decryption benchmark
                let start = Instant::now();
                for encrypted_data in &encrypted_vec {
                    let encrypted_bytes = PyBytes::new(py, encrypted_data);
                    let _ = decrypt_message(py, &encrypted_bytes.as_borrowed(), &key.as_borrowed())?;
                }
                let decrypt_duration = start.elapsed();

                let encrypt_throughput = (size * iterations) as f64 / encrypt_duration.as_secs_f64() / 1_000_000.0;
                let decrypt_throughput = (size * iterations) as f64 / decrypt_duration.as_secs_f64() / 1_000_000.0;

                println!("Size {} bytes:", size);
                println!("  Encrypt: {:?} for {} ops ({:.2} MB/s)",
                         encrypt_duration, iterations, encrypt_throughput);
                println!("  Decrypt: {:?} for {} ops ({:.2} MB/s)",
                         decrypt_duration, iterations, decrypt_throughput);
            }

            Ok(())
        })
    }

    /// Concurrent usage test (if threading is supported)
    #[test]
    fn test_concurrent_usage() -> PyResult<()> {
        pyo3::prepare_freethreaded_python();

        use std::thread;

        let handles: Vec<_> = (0..4).map(|i| {
            thread::spawn(move || {
                Python::with_gil(|py| -> PyResult<()> {
                    let key = generate_key(py)?;
                    let message = PyBytes::new(py, format!("Thread {} message", i).as_bytes());

                    for _ in 0..10 {
                        let encrypted = encrypt_message(py, &message.as_borrowed(), &key.as_borrowed())?;
                        let decrypted = decrypt_message(py, &encrypted.as_borrowed(), &key.as_borrowed())?;
                        assert_eq!(decrypted.as_bytes(), message.as_bytes());
                    }

                    Ok(())
                }).unwrap();
            })
        }).collect();

        for handle in handles {
            handle.join().unwrap();
        }

        Ok(())
    }
}