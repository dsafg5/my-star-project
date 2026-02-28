use sta_rs::*;
use star_test_utils::*;

#[test]
fn test_key_recovery_from_shares() {
    let mut messages = Vec::new();
    let threshold = 2;
    let epoch = "t";
    let measurement = SingleMeasurement::new("hello world".as_bytes());

    let mg = MessageGenerator::new(measurement, threshold, epoch.as_bytes());
    for _ in 0..3 {
        let mut rnd = [0u8; 32];
        mg.sample_local_randomness(&mut rnd);
        messages.push(Message::generate(&mg, &mut rnd, None).unwrap());
    }

    let shares: Vec<Share> = messages.iter().map(|m| m.share.clone()).collect();
    let value = share_recover(&shares).unwrap().get_message();

    let mut enc_key = vec![0u8; 16];
    derive_ske_key(&value, epoch.as_bytes(), &mut enc_key);

    println!("Derived key: {:?}", enc_key);
    assert_eq!(enc_key.len(), 16);
}

use sta_rs::*;
use star_test_utils::*;

#[test]
fn test_key_recovery_from_shares_and_decrypt() {
    let mut messages = Vec::new();
    let threshold = 2;
    let epoch = "t";
    let measurement = SingleMeasurement::new("hello world".as_bytes());

    let mg = MessageGenerator::new(measurement, threshold, epoch.as_bytes());
    for _ in 0..3 {
        let mut rnd = [0u8; 32];
        mg.sample_local_randomness(&mut rnd);
        messages.push(Message::generate(&mg, &mut rnd, None).unwrap());
    }

    // Step 1: 从 Message 中提取 Share 并恢复密钥种子 r1
    let shares: Vec<Share> = messages.iter().map(|m| m.share.clone()).collect();
    let r1 = share_recover(&shares).unwrap().get_message();

    // Step 2: 用 r1 和 epoch 派生出对称密钥
    let mut enc_key = vec![0u8; 16];
    derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key);
    println!("Derived key: {:?}", enc_key);

    // Step 3: 解密第一个 Message 中的密文
    let ciphertext = &messages[0].ciphertext;
    let plaintext = ciphertext.decrypt(&enc_key, "star_encrypt");

    // Step 4: 解析明文结构
    let mut slice = &plaintext[..];
    let measurement_bytes = load_bytes(slice).expect("Failed to parse measurement");
    slice = &slice[4 + measurement_bytes.len()..];

    if !slice.is_empty() {
        let aux_bytes = load_bytes(slice).unwrap();
        println!("Auxiliary data: {:?}", aux_bytes);
    } else {
        println!("No auxiliary data.");
    }

    // Step 5: 验证解密是否成功
    assert_eq!(measurement_bytes, b"hello world");
    assert_eq!(enc_key.len(), 16);
    println!("Recovered measurement: {:?}", std::str::from_utf8(&measurement_bytes).unwrap());
}

