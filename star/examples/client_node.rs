use sta_rs::*;
use star_test_utils::*;
use std::collections::HashMap;
use std::fs::File;

fn main() {
    let num_clients = 5;
    let threshold = 3;
    let num_rounds = 5;
    
    let file_path = "样例数据.csv"; 
    
    let file = File::open(file_path).expect("❌ 无法打开 CSV 文件");
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(file);
    
    let mut all_records = Vec::new();
    for result in rdr.records() {
        if let Ok(record) = result {
            all_records.push(record);
        }
    }

    println!("⚙️ [客户端节点] 启动 -> 共有 {} 个客户端参与，进行 {} 轮加密上报", num_clients, num_rounds);

    // 改为存储 Vec<u8> 字节数组，绕过序列化限制
    let mut all_rounds_inbox: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

    for round in 0..num_rounds {
        let data_col_index = 2 + round; 
        let epoch = format!("round_epoch_{}", round); 

        println!("🚀 开始加密第 {} 轮数据 (Epoch: {})...", round + 1, epoch);

        let mut round_messages = Vec::new();

        for client_id in 1..=num_clients {
            for record in &all_records {
                let comment = record.get(1).unwrap_or("").trim();
                let data = record.get(data_col_index).unwrap_or("").trim();
                
                if data.is_empty() { 
                    continue; 
                }

                let measurement_str = format!("{}: {}", comment, data);
                let messages = client_generate_messages(&measurement_str, threshold, &epoch, 1);
                
                // 序列化前，调用内置的 to_bytes() 转为字节数组
                for msg in messages {
                    round_messages.push(msg.to_bytes());
                }
            }
            println!("  [客户端 {}] 已完成第 {} 轮加密", client_id, round + 1);
        }
        all_rounds_inbox.insert(epoch, round_messages);
    }

    println!("\n💾 正在将所有密文对象打包并序列化...");
    
    let file = File::create("client_encrypted.json").expect("❌ 无法创建 client_encrypted.json");
    serde_json::to_writer_pretty(file, &all_rounds_inbox).expect("❌ JSON 序列化失败");
    
    println!("✅ [客户端节点] 运行完毕！密文已成功导出至 -> client_encrypted.json");
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
//     let num_clients = 5;
//     let threshold = 3;
//     let num_rounds = 5;
    
//     let file_path = "样例数据.csv"; 
    
//     let file = File::open(file_path).expect("❌ 无法打开 CSV 文件");
//     let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(file);
    
//     let mut all_records = Vec::new();
//     for result in rdr.records() {
//         if let Ok(record) = result {
//             all_records.push(record);
//         }
//     }

//     println!("⚙️ [客户端节点] 启动 -> 共有 {} 个客户端参与，进行 {} 轮加密上报", num_clients, num_rounds);

//     // 存储所有轮次的密文：Key 为 epoch 字符串，Value 为生成的 Message 数组
//     let mut all_rounds_inbox: HashMap<String, Vec<Message>> = HashMap::new();

//     for round in 0..num_rounds {
//         let data_col_index = 2 + round; 
//         let epoch = format!("round_epoch_{}", round); 

//         println!("🚀 开始加密第 {} 轮数据 (Epoch: {})...", round + 1, epoch);

//         let mut round_messages = Vec::new();

//         for client_id in 1..=num_clients {
//             for record in &all_records {
//                 let comment = record.get(1).unwrap_or("").trim();
//                 let data = record.get(data_col_index).unwrap_or("").trim();
                
//                 if data.is_empty() { 
//                     continue; 
//                 }

//                 let measurement_str = format!("{}: {}", comment, data);
//                 let messages = client_generate_messages(&measurement_str, threshold, &epoch, 1);
//                 round_messages.extend(messages);
//             }
//             println!("  [客户端 {}] 已完成第 {} 轮加密", client_id, round + 1);
//         }
//         all_rounds_inbox.insert(epoch, round_messages);
//     }

//     println!("\n💾 正在将所有密文对象打包并序列化...");
    
//     // 将密文直接导出为可被服务器读取的 JSON 结构
//     let file = File::create("client_encrypted.json").expect("❌ 无法创建 client_encrypted.json");
//     serde_json::to_writer_pretty(file, &all_rounds_inbox).expect("❌ JSON 序列化失败，请确保 Message 实现了 Serialize");
    
//     println!("✅ [客户端节点] 运行完毕！密文已成功导出至 -> client_encrypted.json");
// }

// fn client_generate_messages(measurement_str: &str, threshold: u32, epoch: &str, count: usize) -> Vec<Message> {
//     let measurement = SingleMeasurement::new(measurement_str.as_bytes());
//     let mg = MessageGenerator::new(measurement, threshold, epoch.as_bytes());

//     let mut messages = Vec::new();
//     for _ in 0..count {
//         let mut rnd = [0u8; 32];
//         mg.sample_local_randomness(&mut rnd); 
//         let msg = Message::generate(&mg, &mut rnd, None).expect("Failed to generate message");
//         messages.push(msg);
//     }
//     messages
// }