use commtools_core::SamRuntime;
use commtools_core::config::SamEndpoint;
use commtools_core::protocol::{Frame, MessageType};
use commtools_core::sam::{
    MAX_TUNNEL_LENGTH, MAX_TUNNEL_QUANTITY, SamError, SamReply, SamSessionConfig, TunnelOptions,
    destination_to_b32,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{Duration, sleep, timeout};

#[test]
fn parses_quoted_sam_fields_without_losing_spaces() {
    let reply =
        SamReply::parse("STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=\"LeaseSet not found\"")
            .expect("valid SAM reply");

    assert_eq!(reply.command(), &["STREAM", "STATUS"]);
    assert_eq!(reply.field("RESULT"), Some("CANT_REACH_PEER"));
    assert_eq!(reply.field("MESSAGE"), Some("LeaseSet not found"));
    assert!(!reply.is_ok());
    assert!(SamReply::parse("HELLO REPLY RESULT=OK RESULT=FAIL").is_err());
    assert!(SamReply::parse("HELLO REPLY MESSAGE=\"unfinished").is_err());

    let generated =
        SamReply::parse("DEST REPLY PUB=public PRIV=private-secret").expect("destination reply");
    assert!(!format!("{generated:?}").contains("private-secret"));
}

#[test]
fn validates_session_tokens_and_tunnel_bounds() {
    assert!(TunnelOptions::new(1, 1).is_ok());
    assert!(TunnelOptions::new(MAX_TUNNEL_LENGTH, MAX_TUNNEL_QUANTITY).is_ok());
    assert!(TunnelOptions::new(0, 1).is_err());
    assert!(TunnelOptions::new(1, MAX_TUNNEL_QUANTITY + 1).is_err());
    assert!(SamSessionConfig::transient("bad id", TunnelOptions::default()).is_err());
    assert!(
        SamSessionConfig::persistent(
            "session",
            "destination\nSESSION CREATE STYLE=STREAM",
            TunnelOptions::default(),
        )
        .is_err()
    );

    let persistent = SamSessionConfig::persistent(
        "session",
        "private-destination-secret",
        TunnelOptions::default(),
    )
    .expect("persistent config");
    assert!(!format!("{persistent:?}").contains("private-destination-secret"));
}

#[test]
fn converts_an_i2p_destination_to_the_established_b32_form() {
    assert_eq!(
        destination_to_b32("YWJj").expect("base64 destination"),
        "xj4bnp4pahh6uqkbidpf3lrceoyagyndsylxvhfucd7wd4qacwwq.b32.i2p"
    );
    assert!(destination_to_b32("not!base64").is_err());
}

#[tokio::test]
async fn endpoint_test_performs_only_sam_hello() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (read_half, mut writer) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        assert_eq!(
            read_line(&mut reader).await,
            "HELLO VERSION MIN=3.0 MAX=3.2"
        );
        writer
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.2\n")
            .await
            .expect("reply");
        let mut remainder = Vec::new();
        reader
            .read_to_end(&mut remainder)
            .await
            .expect("endpoint EOF");
        assert!(remainder.is_empty());
    });

    let endpoint = SamEndpoint::new(address.ip().to_string(), address.port()).expect("endpoint");
    let reply = SamRuntime::test_endpoint(&endpoint)
        .await
        .expect("SAM test");
    assert!(reply.is_ok());
    server.await.expect("server task");
}

#[tokio::test]
async fn runtime_streams_frames_and_closes_registered_streams() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (control, _) = listener.accept().await.expect("control accept");
        let (control_read, mut control_writer) = control.into_split();
        let mut control_reader = BufReader::new(control_read);
        complete_persistent_session(&mut control_reader, &mut control_writer).await;

        let (stream, _) = listener.accept().await.expect("stream accept");
        let (stream_read, mut stream_writer) = stream.into_split();
        let mut stream_reader = BufReader::new(stream_read);
        assert_eq!(
            read_line(&mut stream_reader).await,
            "HELLO VERSION MIN=3.0 MAX=3.2"
        );
        stream_writer
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.2\n")
            .await
            .expect("stream hello");
        assert_eq!(
            read_line(&mut stream_reader).await,
            "STREAM CONNECT ID=test-session DESTINATION=peer.b32.i2p"
        );
        stream_writer
            .write_all(b"STREAM STATUS RESULT=OK\n")
            .await
            .expect("connect reply");

        assert_eq!(read_line(&mut stream_reader).await, "YWJj");
        let received = Frame::read_from(&mut stream_reader)
            .await
            .expect("read frame");
        assert_eq!(
            received,
            Frame::new(MessageType::U, 7, b"outbound".to_vec())
        );
        Frame::new(MessageType::D, 8, b"inbound".to_vec())
            .write_to(&mut stream_writer)
            .await
            .expect("write frame");
        stream_writer.flush().await.expect("flush frame");

        let mut stream_remainder = Vec::new();
        timeout(
            Duration::from_secs(1),
            stream_reader.read_to_end(&mut stream_remainder),
        )
        .await
        .expect("stream close timeout")
        .expect("stream EOF");
        assert!(stream_remainder.is_empty());

        let mut control_remainder = Vec::new();
        timeout(
            Duration::from_secs(1),
            control_reader.read_to_end(&mut control_remainder),
        )
        .await
        .expect("control close timeout")
        .expect("control EOF");
    });

    let runtime = runtime_for(address);
    let config = persistent_config();
    let info = runtime
        .create_session(&config)
        .await
        .expect("create session");
    assert!(!format!("{info:?}").contains("private-destination"));
    assert_eq!(info.b32, destination_to_b32("YWJj").expect("b32"));
    let connection = runtime.connect("peer.b32.i2p").await.expect("connect");
    assert_eq!(runtime.registered_stream_count(), 1);
    runtime
        .send_destination_prelude(&connection, "YWJj")
        .await
        .expect("destination prelude");
    runtime
        .send_frame(
            &connection,
            &Frame::new(MessageType::U, 7, b"outbound".to_vec()),
        )
        .await
        .expect("send frame");
    assert_eq!(
        connection.recv_frame().await.expect("receive frame"),
        Frame::new(MessageType::D, 8, b"inbound".to_vec())
    );
    runtime
        .close_stream(&connection)
        .await
        .expect("close stream");
    assert_eq!(runtime.registered_stream_count(), 0);
    runtime.shutdown().await.expect("shutdown runtime");
    assert!(runtime.is_closed());
    server.await.expect("server task");
}

#[tokio::test]
async fn shutdown_drains_a_late_successful_stream_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let (connect_seen_tx, connect_seen_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (control, _) = listener.accept().await.expect("control accept");
        let (control_read, mut control_writer) = control.into_split();
        let mut control_reader = BufReader::new(control_read);
        complete_persistent_session(&mut control_reader, &mut control_writer).await;

        let (stream, _) = listener.accept().await.expect("stream accept");
        let (stream_read, mut stream_writer) = stream.into_split();
        let mut stream_reader = BufReader::new(stream_read);
        assert_eq!(
            read_line(&mut stream_reader).await,
            "HELLO VERSION MIN=3.0 MAX=3.2"
        );
        stream_writer
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.2\n")
            .await
            .expect("stream hello");
        assert_eq!(
            read_line(&mut stream_reader).await,
            "STREAM CONNECT ID=test-session DESTINATION=late-peer.b32.i2p"
        );
        connect_seen_tx.send(()).expect("connect notification");
        sleep(Duration::from_millis(50)).await;
        stream_writer
            .write_all(b"STREAM STATUS RESULT=OK\n")
            .await
            .expect("late connect reply");

        let mut stream_remainder = Vec::new();
        timeout(
            Duration::from_secs(1),
            stream_reader.read_to_end(&mut stream_remainder),
        )
        .await
        .expect("late stream close timeout")
        .expect("late stream EOF");
        assert!(stream_remainder.is_empty());

        let mut control_remainder = Vec::new();
        timeout(
            Duration::from_secs(1),
            control_reader.read_to_end(&mut control_remainder),
        )
        .await
        .expect("control close timeout")
        .expect("control EOF");
    });

    let runtime = runtime_for(address);
    runtime
        .create_session(&persistent_config())
        .await
        .expect("create session");
    let connecting_runtime = runtime.clone();
    let connect =
        tokio::spawn(async move { connecting_runtime.connect("late-peer.b32.i2p").await });
    connect_seen_rx.await.expect("connect command observed");

    runtime.shutdown().await.expect("clean runtime shutdown");
    assert!(runtime.is_closed());
    assert_eq!(runtime.active_operation_count(), 0);
    assert!(matches!(
        connect.await.expect("connect task"),
        Err(SamError::Cancelled)
    ));
    server.await.expect("server task");
}

fn runtime_for(address: std::net::SocketAddr) -> SamRuntime {
    SamRuntime::new(
        SamEndpoint::new(address.ip().to_string(), address.port()).expect("runtime endpoint"),
    )
}

fn persistent_config() -> SamSessionConfig {
    SamSessionConfig::persistent(
        "test-session",
        "private-destination",
        TunnelOptions::default(),
    )
    .expect("session config")
}

async fn complete_persistent_session<R, W>(reader: &mut R, writer: &mut W)
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    assert_eq!(read_line(reader).await, "HELLO VERSION MIN=3.0 MAX=3.2");
    writer
        .write_all(b"HELLO REPLY RESULT=OK VERSION=3.2\n")
        .await
        .expect("control hello");
    assert_eq!(
        read_line(reader).await,
        "SESSION CREATE STYLE=STREAM ID=test-session DESTINATION=private-destination SIGNATURE_TYPE=7 OPTION inbound.length=2 outbound.length=2 inbound.quantity=3 outbound.quantity=3"
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
