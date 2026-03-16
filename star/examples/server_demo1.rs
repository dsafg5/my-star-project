use sta_rs::*;
use star_test_utils::*;
use std::collections::HashMap;
use std::fs::File;

fn main() {
    let num_clients = 5;
    let threshold = 3;
    let num_rounds = 5;
    
    // 请根据实际情况调整相对路径，例如 "../样例数据.csv"
    let file_path = "样例数据.csv"; 
    
    let file = File::open(file_path).expect("❌ 无法打开 CSV 文件");
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(file);
    
    let mut all_records = Vec::new();
    let mut row_order = Vec::new();
    let mut results_map: HashMap<String, Vec<String>> = HashMap::new();

    for result in rdr.records() {
        if let Ok(record) = result {
            all_records.push(record.clone());
            
            let comment = record.get(1).unwrap_or("").trim().to_string();
            if !comment.is_empty() && !row_order.contains(&comment) {
                row_order.push(comment.clone());
                results_map.insert(comment, vec!["-".to_string(); num_rounds]);
            }
        }
    }

    println!("⚙️ 系统启动 -> 共有 {} 个客户端，解密阈值 {}，将进行 {} 轮聚合数据上传", num_clients, threshold, num_rounds);

    for round in 0..num_rounds {
        let data_col_index = 2 + round; 
        let epoch = format!("round_epoch_{}", round); 

        println!("\n===========================================================");
        println!("🚀 开始第 {} 轮上传 (Epoch: {}) -> 目标列: 索引 {}", round + 1, epoch, data_col_index);
        println!("===========================================================");

        let mut server_inbox: Vec<Message> = Vec::new();

        for client_id in 1..=num_clients {
            for record in &all_records {
                let comment = record.get(1).unwrap_or("").trim();
                let data = record.get(data_col_index).unwrap_or("").trim();
                
                if data.is_empty() { 
                    continue; 
                }

                let measurement_str = format!("{}: {}", comment, data);
                let messages = client_generate_messages(&measurement_str, threshold, &epoch, 1);
                server_inbox.extend(messages);
            }
            println!("  [客户端 {}] 已完成第 {} 轮的数据加密与上报", client_id, round + 1);
        }

        println!("  📤 本轮所有客户端上传完毕！聚合器共收到 {} 条混淆消息。\n", server_inbox.len());

        let mut grouped_messages: HashMap<Vec<u8>, Vec<Message>> = HashMap::new();
        for msg in server_inbox {
            grouped_messages.entry(msg.tag.to_vec()).or_default().push(msg);
        }

        let mut success_count = 0;
        let mut fail_count = 0;

        println!("  --- 聚合器解密结果 ---");
        for (_tag, group) in grouped_messages {
            let msg_count = group.len();
            
            if msg_count >= threshold as usize {
                let shares: Vec<Share> = group.iter().map(|m| m.share.clone()).collect();
                let r1 = share_recover(&shares).expect("❌ 份额恢复失败").get_message();
                
                let mut enc_key = vec![0u8; 16];
                derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key); 
                
                let plaintext = group[0].ciphertext.decrypt(&enc_key, "star_encrypt");
                let slice = &plaintext[..];
                let measurement_bytes = load_bytes(slice).unwrap();
                let result_str = std::str::from_utf8(&measurement_bytes).unwrap();
                
                println!("  ✅ [组解密成功] 聚合 {} 份 -> {}", msg_count, result_str);
                success_count += 1;

                let parts: Vec<&str> = result_str.splitn(2, ": ").collect();
                if parts.len() == 2 {
                    let comment_key = parts[0];
                    let value = parts[1];
                    if let Some(vals) = results_map.get_mut(comment_key) {
                        vals[round] = value.to_string(); 
                    }
                }
            } else {
                fail_count += 1;
            }
        }

        println!("\n  📊 第 {} 轮最终统计: 成功输出 {} 条数据组，因未达阈值丢弃 {} 条。", round + 1, success_count, fail_count);
    }

    println!("\n===========================================================");
    println!("💾 正在将所有轮次的聚合结果导出到 result.csv ...");
    
    let mut wtr = csv::Writer::from_path("result.csv").expect("❌ 无法创建 result.csv 文件");
    
    let mut header = vec!["数据属性 (中文注释)".to_string()];
    for r in 0..num_rounds {
        header.push(format!("第{}轮聚合结果", r + 1));
    }
    wtr.write_record(&header).expect("❌ 写入表头失败");

    for comment in row_order {
        if let Some(vals) = results_map.get(&comment) {
            let mut row = vec![comment.clone()];
            row.extend(vals.clone());
            wtr.write_record(&row).expect("❌ 写入数据行失败");
        }
    }
    
    wtr.flush().expect("❌ 刷新 CSV 缓冲区失败");
    println!("✅ 导出完成！请查看当前目录下的 result.csv 文件，各行各列已标注清晰！");
    println!("===========================================================\n");
}

fn client_generate_messages(measurement_str: &str, threshold: u32, epoch: &str, count: usize) -> Vec<Message> {
    let measurement = SingleMeasurement::new(measurement_str.as_bytes());
    let mg = MessageGenerator::new(measurement, threshold, epoch.as_bytes());

    let mut messages = Vec::new();
    for _ in 0..count {
        let mut rnd = [0u8; 32];
        mg.sample_local_randomness(&mut rnd); 
        let msg = Message::generate(&mg, &mut rnd, None).expect("Failed to generate message");
        messages.push(msg);
    }
    messages
}
// use sta_rs::*;
// use star_test_utils::*;
// use std::collections::HashMap;
// use std::fs::File;

// fn main() {
//     // ==========================================
//     // ⚙️ 自定义配置区 (你可以随意修改这里的数字)
//     // ==========================================
//     let num_clients = 100; // 自定义：模拟多少个客户端读取了文件并上传数据
//     let threshold = 3;   // 自定义：聚合器解密阈值（至少需要几个相同数据才能解密）
    
//     let epoch = "t";
//     let file_path = "样例数据"; // 确保路径对应你运行的实际位置
//     // ==========================================

//     println!("⚙️ 系统启动 -> 共有 {} 个客户端上报数据，聚合器解密阈值为 {} \n", num_clients, threshold);

//     let file = File::open(file_path).expect("❌ 无法打开 CSV 文件，请检查路径");
//     let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(file);

//     // [模拟网络层] 聚合器的“大收件箱”，存放所有客户端发来的打乱的加密消息
//     let mut server_inbox: Vec<Message> = Vec::new();

//     println!("--- [1. 客户端阶段] 各个客户端开始读取文件并独立生成加密份额 ---");
    
//     // 逐行读取文件，模拟所有客户端都获取了这些数据
//     for result in rdr.records() {
//         let record = result.expect("❌ 读取 CSV 行失败");
//         let comment = record.get(1).unwrap_or("").trim();
//         let data = record.get(2).unwrap_or("").trim();
        
//         // 过滤空数据行
//         if data.is_empty() { 
//             continue; 
//         }

//         // 拼接出原始明文（例如："目标编码: BDW582"）
//         let measurement_str = format!("{}: {}", comment, data);
        
//         // 核心逻辑：针对每一行数据，模拟 `num_clients` 个客户端分别独立生成加密份额
//         // 因为每个客户端生成的随机性（randomness）不同，所以虽然明文一样，但密文和份额都不同
//         let messages = client_generate_messages(&measurement_str, threshold, epoch, num_clients);
        
//         // 客户端通过网络发送给聚合器（全部扔进同一个收件箱）
//         server_inbox.extend(messages);
//     }

//     println!("📤 所有客户端上传完毕！聚合器收件箱共收到 {} 条混淆的加密消息。\n", server_inbox.len());
//     println!("--- [2. 聚合器阶段] 聚合器开始盲分组并尝试解密 ---");
    
//     // 步骤 A: 聚合器依靠 Tag（标签）进行盲分组
//     let mut grouped_messages: HashMap<Vec<u8>, Vec<Message>> = HashMap::new();
//     for msg in server_inbox {
//         // 具有相同明文的消息会产生相同的 Tag，以此归类
//         grouped_messages.entry(msg.tag.to_vec()).or_default().push(msg);
//     }

//     let mut success_count = 0;
//     let mut fail_count = 0;

//     // 步骤 B: 对每个数据组判断是否达到阈值，并执行解密
//     for (_tag, group) in grouped_messages {
//         let msg_count = group.len();
        
//         if msg_count >= threshold as usize {
//             // ✅ 达到或超过阈值，满足解密条件
//             let shares: Vec<Share> = group.iter().map(|m| m.share.clone()).collect();
//             let r1 = share_recover(&shares).expect("❌ 份额恢复失败").get_message();
            
//             let mut enc_key = vec![0u8; 16];
//             derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key);
            
//             let plaintext = group[0].ciphertext.decrypt(&enc_key, "star_encrypt");
//             let slice = &plaintext[..];
//             let measurement_bytes = load_bytes(slice).unwrap();
            
//             let result_str = std::str::from_utf8(&measurement_bytes).unwrap();
//             println!("✅ [解密成功] 凑齐了 {} 个客户端的份额 -> 还原数据: {}", msg_count, result_str);
//             success_count += 1;
//         } else {
//             // ❌ 未达阈值，丢弃处理
//             println!("🔒 [隐私保护] 仅有 {} 个客户端上报，未达阈值 {}，服务器无法解密", msg_count, threshold);
//             fail_count += 1;
//         }
//     }

//     println!("\n📊 最终统计: 聚合器成功解密输出 {} 条数据，因未达阈值丢弃 {} 条数据。", success_count, fail_count);
// }

// // ---------------------------------------------------------
// // 客户端加密函数 (保持不变)
// // ---------------------------------------------------------
// fn client_generate_messages(measurement_str: &str, threshold: u32, epoch: &str, count: usize) -> Vec<Message> {
//     let measurement = SingleMeasurement::new(measurement_str.as_bytes());
//     let mg = MessageGenerator::new(measurement, threshold, epoch.as_bytes());

//     let mut messages = Vec::new();
//     for _ in 0..count {
//         let mut rnd = [0u8; 32];
//         mg.sample_local_randomness(&mut rnd); // STARLite 本地随机性采样
//         let msg = Message::generate(&mg, &mut rnd, None).expect("Failed to generate message");
//         messages.push(msg);
//     }
//     messages
// }