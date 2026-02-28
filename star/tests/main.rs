use sta_rs::*;
use star_test_utils::*;

#[test]
fn test_server_decrypt() {
    let threshold = 2;
    let epoch = "t";
    let messages = client_generate_messages("hello world", threshold, epoch, 3);
    server_aggregate_and_decrypt(&messages, threshold, epoch);
}


fn client_generate_messages(measurement_str: &str, threshold: u32, epoch: &str, count: usize) -> Vec<Message> {
    let measurement = SingleMeasurement::new(measurement_str.as_bytes());
    let mg = MessageGenerator::new(measurement, threshold, epoch.as_bytes());

    let mut messages = Vec::new();
    for _ in 0..count {
        let mut rnd = [0u8; 32];
        mg.sample_local_randomness(&mut rnd); // STARLite 模式
        let msg = Message::generate(&mg, &mut rnd, None).expect("Failed to generate message");
        messages.push(msg);
    }
    messages
}

// fn server_aggregate_and_decrypt(messages: &[Message], threshold: u32, epoch: &str) {
//     // 聚合 share 并恢复密钥种子 r1
//     let shares: Vec<Share> = messages.iter().map(|m| m.share.clone()).collect();
//     let r1 = share_recover(&shares).expect("Failed to recover share").get_message();

//     // 派生密钥
//     let mut enc_key = vec![0u8; 16];
//     derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key);
//     println!("Derived key: {:?}", enc_key);

//     // 解密第一个 message 的 ciphertext
//     let ciphertext = &messages[0].ciphertext;
//     let plaintext = ciphertext.decrypt(&enc_key, "star_encrypt");

//     // 解析测量值和 auxiliary data
//     let mut slice = &plaintext[..];
//     let measurement_bytes = load_bytes(slice).expect("Failed to load measurement");
//     slice = &slice[4 + measurement_bytes.len()..];

//     if !slice.is_empty() {
//         let aux_bytes = load_bytes(slice).unwrap();
//         println!("Auxiliary data: {:?}", aux_bytes);
//     } else {
//         println!("No auxiliary data.");
//     }

//     // 校验
//     assert_eq!(measurement_bytes, b"hello world");
//     assert_eq!(enc_key.len(), 16);
//     println!("Recovered measurement: {:?}", std::str::from_utf8(&measurement_bytes).unwrap());
// }

fn server_aggregate_and_decrypt(messages: &[Message], threshold: u32, epoch: &str) {
    println!("--- [服务器开始聚合解密流程] ---");
    println!("收到 message 数量: {}", messages.len());
    println!("期望阈值: {}", threshold);
    println!("使用 epoch: {}", epoch);

    // Step 1: 聚合 share 并恢复密钥种子 r1
    println!("\n[1] 正在收集 shares...");
    let shares: Vec<Share> = messages.iter().map(|m| m.share.clone()).collect();
    println!("提取 share 数量: {}", shares.len());

    let r1 = share_recover(&shares)
        .expect("❌ share 恢复失败")
        .get_message();
    println!("[1] 密钥种子 r1: {:?}", r1);

    // Step 2: 派生密钥
    println!("\n[2] 正在派生对称加密密钥...");
    let mut enc_key = vec![0u8; 16];
    derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key);
    println!("[2] 派生出的 AES 密钥: {:?}", enc_key);

    // Step 3: 解密密文
    println!("\n[3] 正在解密第一个消息的 ciphertext...");
    let ciphertext = &messages[0].ciphertext;
    let plaintext = ciphertext.decrypt(&enc_key, "star_encrypt");
    println!("[3] 解密后 plaintext 长度: {}", plaintext.len());

    // Step 4: 解析明文结构（测量值 + auxiliary data）
    println!("\n[4] 正在解析解密后的明文...");
    let mut slice = &plaintext[..];
    let measurement_bytes = load_bytes(slice).expect("❌ 测量值解析失败");
    println!("[4] 还原测量值字节: {:?}", measurement_bytes);
    slice = &slice[4 + measurement_bytes.len()..];

    if !slice.is_empty() {
        let aux_bytes = load_bytes(slice).unwrap();
        println!("[4] 辅助数据（auxiliary data）: {:?}", aux_bytes);
    } else {
        println!("[4] 无辅助数据（aux）");
    }

    // Step 5: 校验解密内容是否正确
    println!("\n[5] 正在进行结果校验...");
    assert_eq!(measurement_bytes, b"hello world", "❌ 测量值不一致");
    assert_eq!(enc_key.len(), 16, "❌ 密钥长度错误");
    println!("✅ 解密成功，测量值为: \"{}\"", std::str::from_utf8(&measurement_bytes).unwrap());
    println!("--- [服务器聚合解密流程结束] ---\n");
}
