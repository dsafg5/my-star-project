use sta_rs::*;
use star_test_utils::*;
use std::fs::File;

fn main() {
    let threshold = 2;
    let epoch = "t";

    // 1. 指定你要读取的表格文件路径（这里以模拟数据表为例，你可以更换为其他几个文件名）
    let file_path = "../样例数据 - 给西电.csv";
    let file = File::open(file_path).expect("❌ 无法打开 CSV 文件，请确认文件就在当前运行命令的目录下");

    // 2. 初始化 CSV 读取器
    // 使用 flexible(true) 是因为部分表格行末尾有多余的空列，这能提高兼容性避免报错
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(file);

    println!("开始读取并处理表格数据: {}\n", file_path);

    // 3. 逐行读取记录并提取数据
    for result in rdr.records() {
        let record = result.expect("❌ 读取 CSV 行数据失败");

        // 提取第2列(索引1) "中文注释" 和 第3列(索引2) "样例数据"
        let comment = record.get(1).unwrap_or("").trim();
        let data = record.get(2).unwrap_or("").trim();

        // 数据清洗：如果遇到“样例数据”为空的行，则跳过不处理
        if data.is_empty() {
            continue;
        }

        // 我们将“中文注释: 样例数据”组合作为最终需要聚合加密的明文，例如 "批号: 745698.0"
        let measurement_str = format!("{}: {}", comment, data);

        println!("============================================================");
        println!("🚀 正在处理数据: {}", measurement_str);

        // 4. 模拟 3 个客户端对这一条数据生成加密消息
        let messages = client_generate_messages(&measurement_str, threshold, epoch, 3);
        
        // 5. 服务器尝试聚合解密（增加一个参数传入 measurement_str，用于断言校验）
        server_aggregate_and_decrypt(&messages, threshold, epoch, &measurement_str);
    }
    
    println!("🎉 所有表格数据处理完毕！");
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

// 注意：这里增加了一个 expected_str 参数，用于动态比对解密出来的结果
fn server_aggregate_and_decrypt(messages: &[Message], threshold: u32, epoch: &str, expected_str: &str) {
    println!("--- [服务器开始聚合解密流程] ---");
    println!("收到 message 数量: {}", messages.len());

    // Step 1: 聚合 share 并恢复密钥种子 r1
    println!("[1] 正在收集 shares...");
    let shares: Vec<Share> = messages.iter().map(|m| m.share.clone()).collect();
    let r1 = share_recover(&shares)
        .expect("❌ share 恢复失败")
        .get_message();

    // Step 2: 派生密钥
    println!("[2] 正在派生对称加密密钥...");
    let mut enc_key = vec![0u8; 16];
    derive_ske_key(&r1, epoch.as_bytes(), &mut enc_key);

    // Step 3: 解密密文
    println!("[3] 正在解密 ciphertext...");
    let ciphertext = &messages[0].ciphertext;
    let plaintext = ciphertext.decrypt(&enc_key, "star_encrypt");

    // Step 4: 解析明文结构（测量值 + auxiliary data）
    println!("[4] 正在解析解密后的明文...");
    let mut slice = &plaintext[..];
    let measurement_bytes = load_bytes(slice).expect("❌ 测量值解析失败");
    slice = &slice[4 + measurement_bytes.len()..];

    if !slice.is_empty() {
        let aux_bytes = load_bytes(slice).unwrap();
        println!("[4] 辅助数据（auxiliary data）: {:?}", aux_bytes);
    }

    // Step 5: 校验解密内容是否正确（动态使用 expected_str 替代之前写死的 "hello world"）
    println!("[5] 正在进行结果校验...");
    assert_eq!(measurement_bytes, expected_str.as_bytes(), "❌ 测量值不一致");
    assert_eq!(enc_key.len(), 16, "❌ 密钥长度错误");
    
    println!("✅ 解密成功，还原出表格数据: \"{}\"", std::str::from_utf8(&measurement_bytes).unwrap());
    println!("--- [服务器聚合解密流程结束] ---\n");
}