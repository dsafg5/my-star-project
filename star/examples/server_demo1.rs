use sta_rs::*;
use star_test_utils::*;
use std::collections::HashMap;
use std::fs::File;

fn main() {
    // ==========================================
    // ⚙️ 自定义配置区 (你可以随意修改这里的数字)
    // ==========================================
    let num_clients = 100; // 自定义：模拟多少个客户端读取了文件并上传数据
    let threshold = 3;   // 自定义：聚合器解密阈值（至少需要几个相同数据才能解密）
    
    let epoch = "t";
    let file_path = "样例数据 - 给西电.csv"; // 确保路径对应你运行的实际位置
    // ==========================================

    println!("⚙️ 系统启动 -> 共有 {} 个客户端上报数据，聚合器解密阈值为 {} \n", num_clients, threshold);

    let file = File::open(file_path).expect("❌ 无法打开 CSV 文件，请检查路径");
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(file);

    // [模拟网络层] 聚合器的“大收件箱”，存放所有客户端发来的打乱的加密消息
    let mut server_inbox: Vec<Message> = Vec::new();

    println!("--- [1. 客户端阶段] 各个客户端开始读取文件并独立生成加密份额 ---");
    
    // 逐行读取文件，模拟所有客户端都获取了这些数据
    for result in rdr.records() {
        let record = result.expect("❌ 读取 CSV 行失败");
        let comment = record.get(1).unwrap_or("").trim();
        let data = record.get(2).unwrap_or("").trim();
        
        // 过滤空数据行
        if data.is_empty() { 
            continue; 
        }

        // 拼接出原始明文（例如："目标编码: BDW582"）
        let measurement_str = format!("{}: {}", comment, data);
        
        // 核心逻辑：针对每一行数据，模拟 `num_clients` 个客户端分别独立生成加密份额
        // 因为每个客户端生成的随机性（randomness）不同，所以虽然明文一样，但密文和份额都不同
        let messages = client_generate_messages(&measurement_str, threshold, epoch, num_clients);
        
        // 客户端通过网络发送给聚合器（全部扔进同一个收件箱）
        server_inbox.extend(messages);
    }

    println!("📤 所有客户端上传完毕！聚合器收件箱共收到 {} 条混淆的加密消息。\n", server_inbox.len());
    println!("--- [2. 聚合器阶段] 聚合器开始盲分组并尝试解密 ---");
    
    // 步骤 A: 聚合器依靠 Tag（标签）进行盲分组
    let mut grouped_messages: HashMap<Vec<u8>, Vec<Message>> = HashMap::new();
    for msg in server_inbox {
        // 具有相同明文的消息会产生相同的 Tag，以此归类
        grouped_messages.entry(msg.tag.to_vec()).or_default().push(msg);
    }

    let mut success_count = 0;
    let mut fail_count = 0;

    // 步骤 B: 对每个数据组判断是否达到阈值，并执行解密
    for (_tag, group) in grouped_messages {
        let msg_count = group.len();
        
        if msg_count >= threshold as usize {
            // ✅ 达到或超过阈值，满足解密条件
            let shares: Vec<Share> = group.iter().map(|m| m.share.clone()).collect();
            let r1 = share_recover(&shares).expect("❌ 份额恢复失败").get_message();
            
            let mut enc_key = vec![0u8; 16];
            derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key);
            
            let plaintext = group[0].ciphertext.decrypt(&enc_key, "star_encrypt");
            let slice = &plaintext[..];
            let measurement_bytes = load_bytes(slice).unwrap();
            
            let result_str = std::str::from_utf8(&measurement_bytes).unwrap();
            println!("✅ [解密成功] 凑齐了 {} 个客户端的份额 -> 还原数据: {}", msg_count, result_str);
            success_count += 1;
        } else {
            // ❌ 未达阈值，丢弃处理
            println!("🔒 [隐私保护] 仅有 {} 个客户端上报，未达阈值 {}，服务器无法解密", msg_count, threshold);
            fail_count += 1;
        }
    }

    println!("\n📊 最终统计: 聚合器成功解密输出 {} 条数据，因未达阈值丢弃 {} 条数据。", success_count, fail_count);
}

// ---------------------------------------------------------
// 客户端加密函数 (保持不变)
// ---------------------------------------------------------
fn client_generate_messages(measurement_str: &str, threshold: u32, epoch: &str, count: usize) -> Vec<Message> {
    let measurement = SingleMeasurement::new(measurement_str.as_bytes());
    let mg = MessageGenerator::new(measurement, threshold, epoch.as_bytes());

    let mut messages = Vec::new();
    for _ in 0..count {
        let mut rnd = [0u8; 32];
        mg.sample_local_randomness(&mut rnd); // STARLite 本地随机性采样
        let msg = Message::generate(&mg, &mut rnd, None).expect("Failed to generate message");
        messages.push(msg);
    }
    messages
}