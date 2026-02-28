use sta_rs::{SingleMeasurement,MessageGenerator,share_recover,AssociatedData, Message, Share, derive_ske_key, load_bytes};
use star_test_utils::*;
use ppoprf::{end_to_end_verifynew, PpClient, PpServer};

#[test]
fn test_server_decrypt_multiple_with_aux() {
    let threshold = 2;
    let epoch = "t";

    // 初始化 POPRF Server
    let ppoprf_server = PpServer::new(vec![0u8]).unwrap();

    // 生成带辅助数据的消息
    let messages =
        client_generate_multiple_measurements_with_aux(threshold, epoch, &ppoprf_server);

    // 聚合解密并打印，包括 auxiliary data
    server_aggregate_and_decrypt(&messages, threshold, epoch);
}

fn client_generate_multiple_measurements_with_aux(
    threshold: u32,
    epoch: &str,
    ppoprf_server: &PpServer,
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

        // 在循环里每次生成这段辅助数据
        let aux_bytes = format!("{}-aux", text).into_bytes();

        let md: u8 = 0;
        for _ in 0..count {
            // OPRF 流程
            let (unblinded, _chk_eval) =
                end_to_end_verifynew(ppoprf_server, text.as_bytes(), md);

            // finalize 出 32 字节随机
            let mut rnd = [0u8; 32];
            PpClient::finalize(text.as_bytes(), md, &unblinded, &mut rnd);

            // 每次都新建 AssociatedData
            let aux = AssociatedData::new(&aux_bytes);
            let msg = Message::generate(&mg, &mut rnd, Some(aux))
                .expect("生成带辅助数据的消息失败");
            messages.push(msg);
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
            let aux_str = std::str::from_utf8(&aux).unwrap_or("[非 UTF-8 数据]");
            println!("包含 auxiliary data: {:?}", aux_str);
        } else {
            println!("无 auxiliary data");
        }
    }
    println!("\n--- [聚合服务器解密流程结束] ---");
}
