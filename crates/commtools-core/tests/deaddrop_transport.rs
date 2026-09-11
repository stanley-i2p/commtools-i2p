use commtools_core::config::SamEndpoint;
use commtools_core::deaddrop::{
    DeaddropClient, DeaddropConfig, GetReplicaStatus, PutReplicaStatus, PutStatus,
    find_pow_counter, verify_pow,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

const DROP_SERVER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p";

#[test]
fn proof_of_work_matches_the_deaddrop_server_material() {
    let counter = find_pow_counter(8, "drop_key", b"offline").expect("proof of work");
    assert_eq!(counter, 411);
    assert!(verify_pow(8, "drop_key", b"offline", counter));
    assert!(!verify_pow(8, "drop_key", b"changed", counter));
    assert!(find_pow_counter(0, "drop_key", b"offline").is_err());
}

#[test]
fn deaddrop_configuration_validates_and_deduplicates_servers() {
    let endpoint = SamEndpoint::default();
    let config = DeaddropConfig::with_pow_bits(
        endpoint.clone(),
        "offline-session",
        [DROP_SERVER.to_string(), DROP_SERVER.to_ascii_uppercase()],
        8,
    )
    .expect("valid config");
    assert_eq!(config.servers(), &[DROP_SERVER.to_string()]);
    assert!(DeaddropConfig::new(endpoint.clone(), "offline-session", Vec::new()).is_err());
    assert!(
        DeaddropConfig::new(endpoint.clone(), "offline-session", ["not-i2p".to_string()]).is_err()
    );
    assert!(
        DeaddropConfig::with_pow_bits(endpoint, "offline-session", [DROP_SERVER.to_string()], 0,)
            .is_err()
    );
}

#[tokio::test]
async fn invalid_operations_are_rejected_before_sam_is_touched() {
    let config = DeaddropConfig::with_pow_bits(
        SamEndpoint::default(),
        "offline-session",
        [DROP_SERVER.to_string()],
        8,
    )
    .expect("config");
    let client = DeaddropClient::new(config);

    assert!(client.put("bad key", b"blob").await.is_err());
    assert!(client.get("bad key").await.is_err());
    assert!(
        client
            .put("valid_key", &vec![0; 256 * 1024 + 1])
            .await
            .is_err()
    );
    assert!(!client.is_started());
}

#[tokio::test]
async fn managed_client_puts_and_gets_through_separate_transient_sessions() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (put_control, _) = listener.accept().await.expect("put control");
        let (put_read, mut put_write) = put_control.into_split();
        let mut put_reader = BufReader::new(put_read);
        complete_transient_session(
            &mut put_reader,
            &mut put_write,
            "drop-test_put",
            "put-private",
        )
        .await;

        let (get_control, _) = listener.accept().await.expect("get control");
        let (get_read, mut get_write) = get_control.into_split();
        let mut get_reader = BufReader::new(get_read);
        complete_transient_session(
            &mut get_reader,
            &mut get_write,
            "drop-test_get",
            "get-private",
        )
        .await;

        let (mut probe_reader, mut probe_writer) =
            accept_connected_stream(&listener, "drop-test_put", DROP_SERVER).await;
        assert_stream_closed(&mut probe_reader).await;
        probe_writer.shutdown().await.expect("probe shutdown");

        let (mut put_stream_reader, mut put_stream_writer) =
            accept_connected_stream(&listener, "drop-test_put", DROP_SERVER).await;
        let put_header = read_line(&mut put_stream_reader).await;
        let fields = put_header.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "PUT");
        assert_eq!(fields[1], "drop_key");
        let blob_size = fields[2].parse::<usize>().expect("blob size");
        let counter = fields[3].parse::<u64>().expect("counter");
        let mut blob = vec![0u8; blob_size];
        put_stream_reader
            .read_exact(&mut blob)
            .await
            .expect("put blob");
        assert_eq!(blob, b"offline");
        assert!(verify_pow(8, "drop_key", &blob, counter));
        put_stream_writer
            .write_all(b"OK\n")
            .await
            .expect("put response");
        put_stream_writer.flush().await.expect("put flush");
        assert_stream_closed(&mut put_stream_reader).await;
        put_stream_writer.shutdown().await.expect("put shutdown");

        let (mut get_stream_reader, mut get_stream_writer) =
            accept_connected_stream(&listener, "drop-test_get", DROP_SERVER).await;
        assert_eq!(read_line(&mut get_stream_reader).await, "GET drop_key");
        get_stream_writer
            .write_all(b"OK 7\noffline")
            .await
            .expect("get response");
        get_stream_writer.flush().await.expect("get flush");
        assert_stream_closed(&mut get_stream_reader).await;
        get_stream_writer.shutdown().await.expect("get shutdown");

        assert_stream_closed(&mut put_reader).await;
        assert_stream_closed(&mut get_reader).await;
    });

    let endpoint = SamEndpoint::new(address.ip().to_string(), address.port()).expect("endpoint");
    let config = DeaddropConfig::with_pow_bits(endpoint, "drop-test", [DROP_SERVER.to_string()], 8)
        .expect("config");
    let client = DeaddropClient::new(config);
    client.start().await.expect("start");

    let put = client.put("drop_key", b"offline").await.expect("put");
    assert_eq!(put.status, PutStatus::Stored);
    assert_eq!(put.successful_servers, [DROP_SERVER.to_string()]);
    assert_eq!(put.replicas.len(), 1);
    assert_eq!(put.replicas[0].status, PutReplicaStatus::Stored);

    let get = client.get("drop_key").await.expect("get");
    assert_eq!(get.replicas.len(), 1);
    assert_eq!(get.replicas[0].status, GetReplicaStatus::Hit);
    assert_eq!(get.replicas[0].blob.as_deref(), Some(b"offline".as_slice()));
    assert_eq!(
        get.hits().collect::<Vec<_>>(),
        [(DROP_SERVER, b"offline".as_slice())]
    );

    client.shutdown().await.expect("shutdown");
    assert!(client.is_closed());
    server.await.expect("server task");
}

async fn complete_transient_session<R, W>(
    reader: &mut R,
    writer: &mut W,
    session_id: &str,
    private_destination: &str,
) where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    assert_eq!(read_line(reader).await, "HELLO VERSION MIN=3.0 MAX=3.2");
    writer
        .write_all(b"HELLO REPLY RESULT=OK VERSION=3.2\n")
        .await
        .expect("hello reply");
    assert_eq!(read_line(reader).await, "DEST GENERATE SIGNATURE_TYPE=7");
    writer
        .write_all(format!("DEST REPLY PUB=YWJj PRIV={private_destination}\n").as_bytes())
        .await
        .expect("destination reply");
    assert_eq!(
        read_line(reader).await,
        format!(
            "SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION={private_destination} SIGNATURE_TYPE=7 OPTION inbound.length=2 outbound.length=2 inbound.quantity=2 outbound.quantity=2"
        )
    );
    writer
        .write_all(b"SESSION STATUS RESULT=OK\n")
        .await
        .expect("session reply");
    assert_eq!(read_line(reader).await, "NAMING LOOKUP NAME=ME");
    writer
        .write_all(b"NAMING REPLY RESULT=OK NAME=ME VALUE=YWJj\n")
        .await
        .expect("lookup reply");
    writer.flush().await.expect("control flush");
}

async fn accept_connected_stream(
    listener: &TcpListener,
    session_id: &str,
    destination: &str,
) -> (
    BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    let (stream, _) = listener.accept().await.expect("stream accept");
    complete_stream_connect(stream, session_id, destination).await
}

async fn complete_stream_connect(
    stream: TcpStream,
    session_id: &str,
    destination: &str,
) -> (
    BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    assert_eq!(
        read_line(&mut reader).await,
        "HELLO VERSION MIN=3.0 MAX=3.2"
    );
    writer
        .write_all(b"HELLO REPLY RESULT=OK VERSION=3.2\n")
        .await
        .expect("stream hello");
    assert_eq!(
        read_line(&mut reader).await,
        format!("STREAM CONNECT ID={session_id} DESTINATION={destination}")
    );
    writer
        .write_all(b"STREAM STATUS RESULT=OK\n")
        .await
        .expect("connect response");
    writer.flush().await.expect("connect flush");
    (reader, writer)
}

async fn read_line<R>(reader: &mut R) -> String
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let count = reader.read_line(&mut line).await.expect("read line");
    assert_ne!(count, 0, "unexpected EOF");
    line.trim_end().to_string()
}

async fn assert_stream_closed<R>(reader: &mut R)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut remainder = Vec::new();
    timeout(Duration::from_secs(1), reader.read_to_end(&mut remainder))
        .await
        .expect("close timeout")
        .expect("stream EOF");
    assert!(remainder.is_empty());
}
