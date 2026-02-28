use sta_rs::*;
use star_test_utils::*;

// 从 ppoprf 根空间导入我们刚才导出的名字
use ppoprf::{ end_to_end_verifynew, PpClient, PpServer };

#[test]
fn test_server_decrypt_multiple() {
    let threshold = 2;
    let epoch = "t";

    // 新增：初始化 POPRF Server
    let ppoprf_server = PpServer::new(vec![0u8]).unwrap();

    // 把服务器实例传进去
    let messages = client_generate_multiple_measurements(threshold, epoch, &ppoprf_server);

    server_aggregate_and_decrypt(&messages, threshold, epoch);
}

// 注意这里签名多了一个参数：ppoprf_server
fn client_generate_multiple_measurements(
    threshold: u32,
    epoch: &str,
    ppoprf_server: &PpServer,   // ← 加上引用
) -> Vec<Message> {
    let mut messages = Vec::new();
    let inputs = [
        ("hello", 3),
        ("world", 2),
        ("unused", 1),
    ];

    for (text, count) in inputs {
        let meas = SingleMeasurement::new(text.as_bytes());
        let mg = MessageGenerator::new(meas, threshold, epoch.as_bytes());

        let md: u8 = 0;
        for _ in 0..count {
            // 调用改名后的函数
            let (unblinded, _chk_eval) =
                end_to_end_verifynew(ppoprf_server, text.as_bytes(), md);

            // finalize 出 32 字节伪随机
            let mut rnd = [0u8; 32];
            PpClient::finalize(text.as_bytes(), md, &unblinded, &mut rnd);

            // 继续用 rnd 生成 STAR 消息
            messages.push(Message::generate(&mg, &mut rnd, None).unwrap());
        }
    }
    messages
}

fn server_aggregate_and_decrypt(messages: &[Message], threshold: u32, epoch: &str) {
    use std::collections::HashMap;

    println!("--- [服务器开始聚合解密流程] ---");
    let mut tag_map: HashMap<Vec<u8>, Vec<&Message>> = HashMap::new();
    for msg in messages {
        tag_map.entry(msg.tag.clone()).or_default().push(msg);
    }
    for (tag, group) in tag_map {
        println!("\n--- 聚合 tag = {:?} 的消息，共 {} 条 ---", tag, group.len());
        if group.len() < threshold as usize {
            println!("❌ 未达到阈值 ({} < {}), 跳过", group.len(), threshold);
            continue;
        }
        let shares: Vec<Share> = group.iter().map(|m| m.share.clone()).collect();
        let r1 = share_recover(&shares).unwrap().get_message();
        let mut enc_key = vec![0u8; 16];
        derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key);

        let ciphertext = &group[0].ciphertext;
        let plaintext = ciphertext.decrypt(&enc_key, "star_encrypt");
        let mut slice = &plaintext[..];
        let measurement_bytes = load_bytes(slice).expect("❌ 测量值解析失败");
        slice = &slice[4 + measurement_bytes.len()..];
        let measurement_str = std::str::from_utf8(&measurement_bytes).unwrap();
        println!("✅ 解密成功，测量值: \"{}\"", measurement_str);

        if !slice.is_empty() {
            let aux = load_bytes(slice).unwrap();
            println!("包含 auxiliary data: {:?}", aux);
        } else {
            println!("无 auxiliary data");
        }
    }
    println!("\n--- [聚合服务器解密流程结束] ---");
}


