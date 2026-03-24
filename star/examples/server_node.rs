use sta_rs::*;
use star_test_utils::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use serde_json::json;

fn main() {
    let threshold = 3;
    let num_rounds = 5;
    let file_path = "样例数据.csv"; 
    
    println!("⚙️ [聚合器节点] 启动 -> 正在读取并准备解密环境...");

    let file = File::open(file_path).expect("❌ 无法打开原始 CSV 文件以获取表头");
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(file);
    let mut row_order = Vec::new();
    let mut results_map: HashMap<String, Vec<String>> = HashMap::new();

    for result in rdr.records() {
        if let Ok(record) = result {
            let comment = record.get(1).unwrap_or("").trim().to_string();
            if !comment.is_empty() && !row_order.contains(&comment) {
                row_order.push(comment.clone());
                results_map.insert(comment, vec!["-".to_string(); num_rounds]);
            }
        }
    }

    println!("📥 正在加载外部密文 client_encrypted.json ...");
    let inbox_file = File::open("client_encrypted.json").expect("❌ 找不到 client_encrypted.json，请先运行客户端程序！");
    let reader = BufReader::new(inbox_file);
    
    // 解析为字节数组
    let raw_inbox: HashMap<String, Vec<Vec<u8>>> = serde_json::from_reader(reader).expect("❌ JSON 解析失败，格式错误");

    for round in 0..num_rounds {
        let epoch = format!("round_epoch_{}", round); 
        println!("\n===========================================================");
        println!("🛡️ 开始聚合解密第 {} 轮 (Epoch: {})", round + 1, epoch);

        let mut success_count = 0;
        let mut fail_count = 0;

        if let Some(server_inbox_bytes) = raw_inbox.get(&epoch) {
            let mut grouped_messages: HashMap<Vec<u8>, Vec<Message>> = HashMap::new();
            
            // 将字节数组还原出 Message 对象
            for b in server_inbox_bytes {
                if let Some(msg) = Message::from_bytes(b) {
                    grouped_messages.entry(msg.tag.to_vec()).or_default().push(msg);
                }
            }

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
        } else {
            println!("  ⚠️ 警告：未找到本轮次的加密数据！");
        }
        println!("  📊 本轮统计: 成功输出 {} 组，因未达阈值丢弃 {} 组", success_count, fail_count);
    }

    println!("\n===========================================================");
    println!("💾 正在导出服务器解密结果 ...");
    
    let mut server_final_json = Vec::new();
    for comment in &row_order {
        if let Some(vals) = results_map.get(comment) {
            let mut round_data = HashMap::new();
            for (i, val) in vals.iter().enumerate() {
                round_data.insert(format!("第{}轮", i + 1), val.clone());
            }
            server_final_json.push(json!({
                "数据属性": comment,
                "聚合结果": round_data
            }));
        }
    }
    
    let server_json_string = serde_json::to_string_pretty(&server_final_json).unwrap();
    let mut server_file = File::create("server_decrypted.json").unwrap();
    server_file.write_all(server_json_string.as_bytes()).unwrap();
    println!("✅ 解密数据已成功导出至 -> server_decrypted.json");

    let mut wtr = csv::Writer::from_path("result.csv").unwrap();
    let mut header = vec!["数据属性 (中文注释)".to_string()];
    for r in 0..num_rounds {
        header.push(format!("第{}轮聚合结果", r + 1));
    }
    wtr.write_record(&header).unwrap();

    for comment in row_order {
        if let Some(vals) = results_map.get(&comment) {
            let mut row = vec![comment.clone()];
            row.extend(vals.clone());
            wtr.write_record(&row).unwrap();
        }
    }
    wtr.flush().unwrap();
    println!("✅ 解密表格已成功导出至 -> result.csv");
    println!("===========================================================\n");
}
// use sta_rs::*;
// use star_test_utils::*;
// use std::collections::HashMap;
// use std::fs::File;
// use std::io::BufReader;
// use std::io::Write;
// use serde_json::json;

// fn main() {
//     let threshold = 3;
//     let num_rounds = 5;
//     let file_path = "样例数据.csv"; 
    
//     println!("⚙️ [聚合器节点] 启动 -> 正在读取并准备解密环境...");

//     // 读取原始 CSV 只是为了获取行标签结构，便于格式化输出
//     let file = File::open(file_path).expect("❌ 无法打开原始 CSV 文件以获取表头");
//     let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(file);
//     let mut row_order = Vec::new();
//     let mut results_map: HashMap<String, Vec<String>> = HashMap::new();

//     for result in rdr.records() {
//         if let Ok(record) = result {
//             let comment = record.get(1).unwrap_or("").trim().to_string();
//             if !comment.is_empty() && !row_order.contains(&comment) {
//                 row_order.push(comment.clone());
//                 results_map.insert(comment, vec!["-".to_string(); num_rounds]);
//             }
//         }
//     }

//     // ---------------------------------------------------------
//     // 核心：读取客户端生成的 client_encrypted.json 文件
//     // ---------------------------------------------------------
//     println!("📥 正在加载外部密文 client_encrypted.json ...");
//     let inbox_file = File::open("client_encrypted.json").expect("❌ 找不到 client_encrypted.json，请先运行客户端程序！");
//     let reader = BufReader::new(inbox_file);
    
//     // 反序列化还原出客户端生成的真实 Message 结构
//     let all_rounds_inbox: HashMap<String, Vec<Message>> = serde_json::from_reader(reader).expect("❌ JSON 解析失败，格式错误");

//     for round in 0..num_rounds {
//         let epoch = format!("round_epoch_{}", round); 
//         println!("\n===========================================================");
//         println!("🛡️ 开始聚合解密第 {} 轮 (Epoch: {})", round + 1, epoch);

//         let mut success_count = 0;
//         let mut fail_count = 0;

//         if let Some(server_inbox) = all_rounds_inbox.get(&epoch) {
//             let mut grouped_messages: HashMap<Vec<u8>, Vec<Message>> = HashMap::new();
//             for msg in server_inbox {
//                 grouped_messages.entry(msg.tag.to_vec()).or_default().push(msg.clone());
//             }

//             for (_tag, group) in grouped_messages {
//                 let msg_count = group.len();
                
//                 if msg_count >= threshold as usize {
//                     let shares: Vec<Share> = group.iter().map(|m| m.share.clone()).collect();
//                     let r1 = share_recover(&shares).expect("❌ 份额恢复失败").get_message();
                    
//                     let mut enc_key = vec![0u8; 16];
//                     derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key); 
                    
//                     let plaintext = group[0].ciphertext.decrypt(&enc_key, "star_encrypt");
//                     let slice = &plaintext[..];
//                     let measurement_bytes = load_bytes(slice).unwrap();
//                     let result_str = std::str::from_utf8(&measurement_bytes).unwrap();
                    
//                     println!("  ✅ [组解密成功] 聚合 {} 份 -> {}", msg_count, result_str);
//                     success_count += 1;

//                     let parts: Vec<&str> = result_str.splitn(2, ": ").collect();
//                     if parts.len() == 2 {
//                         let comment_key = parts[0];
//                         let value = parts[1];
//                         if let Some(vals) = results_map.get_mut(comment_key) {
//                             vals[round] = value.to_string(); 
//                         }
//                     }
//                 } else {
//                     fail_count += 1;
//                 }
//             }
//         } else {
//             println!("  ⚠️ 警告：未找到本轮次的加密数据！");
//         }
//         println!("  📊 本轮统计: 成功输出 {} 组，因未达阈值丢弃 {} 组", success_count, fail_count);
//     }

//     println!("\n===========================================================");
//     println!("💾 正在导出服务器解密结果 ...");
    
//     // 导出解密 JSON
//     let mut server_final_json = Vec::new();
//     for comment in &row_order {
//         if let Some(vals) = results_map.get(comment) {
//             let mut round_data = HashMap::new();
//             for (i, val) in vals.iter().enumerate() {
//                 round_data.insert(format!("第{}轮", i + 1), val.clone());
//             }
//             server_final_json.push(json!({
//                 "数据属性": comment,
//                 "聚合结果": round_data
//             }));
//         }
//     }
    
//     let server_json_string = serde_json::to_string_pretty(&server_final_json).unwrap();
//     let mut server_file = File::create("server_decrypted.json").unwrap();
//     server_file.write_all(server_json_string.as_bytes()).unwrap();
//     println!("✅ 解密数据已成功导出至 -> server_decrypted.json");

//     // 导出解密 CSV
//     let mut wtr = csv::Writer::from_path("result.csv").unwrap();
//     let mut header = vec!["数据属性 (中文注释)".to_string()];
//     for r in 0..num_rounds {
//         header.push(format!("第{}轮聚合结果", r + 1));
//     }
//     wtr.write_record(&header).unwrap();

//     for comment in row_order {
//         if let Some(vals) = results_map.get(&comment) {
//             let mut row = vec![comment.clone()];
//             row.extend(vals.clone());
//             wtr.write_record(&row).unwrap();
//         }
//     }
//     wtr.flush().unwrap();
//     println!("✅ 解密表格已成功导出至 -> result.csv");
//     println!("===========================================================\n");
// }