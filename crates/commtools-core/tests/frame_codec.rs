use commtools_core::constants::{
    FRAME_HEADER_LEN, FRAME_MAGIC, MAX_FRAME_PAYLOAD_SIZE, PROTOCOL_VERSION,
};
use commtools_core::protocol::{Frame, MessageType, ProtocolError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn encodes_the_established_wire_layout() {
    let frame = Frame::new(MessageType::U, 0x0102_0304_0506_0708, b"abc".to_vec());
    let encoded = frame.encode().expect("frame should encode");

    let expected = vec![
        0x89, b'I', b'2', b'P', 3, b'U', 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 3, b'a', b'b', b'c',
    ];
    assert_eq!(encoded, expected);
}

#[test]
fn decodes_the_established_wire_layout() {
    let encoded = [
        0x89, b'I', b'2', b'P', 3, b'L', 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef,
    ];

    let decoded = Frame::decode(&encoded).expect("frame should decode");
    assert_eq!(decoded.message_type, MessageType::L);
    assert_eq!(decoded.message_id, 9);
    assert_eq!(decoded.payload, [0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn every_established_message_type_round_trips() {
    for message_type in MessageType::ALL {
        let frame = Frame::new(message_type, 7, [message_type.as_u8()]);
        let decoded = Frame::decode(&frame.encode().expect("encode")).expect("decode");
        assert_eq!(decoded, frame);
    }
}

#[test]
fn rejects_malformed_headers_and_lengths() {
    assert!(matches!(Frame::decode(&[]), Err(ProtocolError::TooShort)));

    let frame = Frame::new(MessageType::S, 1, b"hello".to_vec());
    let encoded = frame.encode().expect("encode");

    let mut invalid_magic = encoded.clone();
    invalid_magic[0] = 0;
    assert!(matches!(
        Frame::decode(&invalid_magic),
        Err(ProtocolError::InvalidMagic)
    ));

    let mut invalid_version = encoded.clone();
    invalid_version[4] = PROTOCOL_VERSION + 1;
    assert!(matches!(
        Frame::decode(&invalid_version),
        Err(ProtocolError::InvalidVersion(4))
    ));

    let mut unknown_type = encoded.clone();
    unknown_type[5] = b'?';
    assert!(matches!(
        Frame::decode(&unknown_type),
        Err(ProtocolError::UnknownMessageType(b'?'))
    ));

    let mut wrong_length = encoded;
    wrong_length[17] = 6;
    assert!(matches!(
        Frame::decode(&wrong_length),
        Err(ProtocolError::LengthMismatch)
    ));
}

#[test]
fn enforces_the_payload_limit_before_encoding_or_allocation() {
    let oversized = Frame::new(MessageType::U, 0, vec![0; MAX_FRAME_PAYLOAD_SIZE + 1]);
    assert!(matches!(
        oversized.encode(),
        Err(ProtocolError::InvalidPayloadSize(size)) if size == MAX_FRAME_PAYLOAD_SIZE + 1
    ));

    let mut header = Vec::with_capacity(FRAME_HEADER_LEN);
    header.extend_from_slice(&FRAME_MAGIC);
    header.push(PROTOCOL_VERSION);
    header.push(MessageType::U.as_u8());
    header.extend_from_slice(&0u64.to_be_bytes());
    header.extend_from_slice(&((MAX_FRAME_PAYLOAD_SIZE + 1) as u32).to_be_bytes());
    assert!(matches!(
        Frame::decode(&header),
        Err(ProtocolError::InvalidPayloadSize(size)) if size == MAX_FRAME_PAYLOAD_SIZE + 1
    ));
}

#[tokio::test]
async fn stream_reader_resynchronizes_on_magic() {
    let frame = Frame::new(MessageType::I, 99, b"index-sync".to_vec());
    let mut stream_bytes = b"unrelated stream bytes".to_vec();
    stream_bytes.extend_from_slice(&frame.encode().expect("encode"));

    let (mut writer, mut reader) = tokio::io::duplex(stream_bytes.len() + 1);
    writer
        .write_all(&stream_bytes)
        .await
        .expect("write fixture");
    drop(writer);

    let decoded = Frame::read_from(&mut reader).await.expect("read frame");
    assert_eq!(decoded, frame);
}

#[tokio::test]
async fn stream_writer_produces_the_same_bytes_as_encode() {
    let frame = Frame::new(MessageType::Z, u64::MAX, b"quit".to_vec());
    let expected = frame.encode().expect("encode");
    let (mut writer, mut reader) = tokio::io::duplex(expected.len() + 1);

    frame.write_to(&mut writer).await.expect("write frame");
    drop(writer);

    let mut actual = Vec::new();
    reader
        .read_to_end(&mut actual)
        .await
        .expect("read frame bytes");
    assert_eq!(actual, expected);
}
