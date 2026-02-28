#[test]
fn test_generate_message_triple() {
    use sta_rs::*;

    let threshold = 2;
    let epoch = "t";
    let measurement = SingleMeasurement::new("hello world".as_bytes());
    let mg = MessageGenerator::new(measurement, threshold, epoch.as_bytes());

    let mut rnd = [0u8; 32];
    mg.sample_local_randomness(&mut rnd); // STARLite 模式

    let Message {
        ciphertext,
        share,
        tag,
    } = Message::generate(&mg, &mut rnd, None)
        .expect("无法生成消息三元组");

    println!("Ciphertext: {:?}", ciphertext.to_bytes());
    println!("Share: {:?}", share);
    println!("Tag: {:?}", tag);
}
