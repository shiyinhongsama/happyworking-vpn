use std::sync::Arc;

use happyworking_vpn_core::{ConnectionState, ErrorCode, Session};

#[test]
fn follows_the_connection_lifecycle() {
    let session = Session::new(8).unwrap();
    let mut events = session.subscribe();

    session.connect().unwrap();
    session.mark_connected().unwrap();
    session.disconnect().unwrap();

    assert_eq!(session.state(), ConnectionState::Disconnected);
    let first = events.try_recv().unwrap();
    assert_eq!(first.from, ConnectionState::Disconnected);
    assert_eq!(first.to, ConnectionState::Connecting);
}

#[test]
fn rejects_a_duplicate_connection_attempt() {
    let session = Session::new(8).unwrap();
    session.connect().unwrap();

    let error = session.connect().unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidState);
    assert_eq!(session.state(), ConnectionState::Connecting);
}

#[test]
fn disconnect_is_idempotent() {
    let session = Session::new(8).unwrap();

    session.disconnect().unwrap();
    session.disconnect().unwrap();

    assert_eq!(session.state(), ConnectionState::Disconnected);
}

#[tokio::test]
async fn cancellation_interrupts_a_pending_connection() {
    let session = Arc::new(Session::new(8).unwrap());
    session.connect().unwrap();
    let waiting = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.cancelled().await })
    };

    session.cancel().unwrap();

    waiting.await.unwrap();
    assert!(session.is_cancelled());
    assert!(session.cancellation_token().is_cancelled());
    assert_eq!(session.state(), ConnectionState::Disconnected);
}

#[test]
fn a_failed_connection_can_be_retried() {
    let session = Session::new(8).unwrap();
    session.connect().unwrap();
    session.fail().unwrap();

    session.connect().unwrap();

    assert_eq!(session.state(), ConnectionState::Connecting);
}

#[tokio::test]
async fn event_delivery_is_bounded() {
    let session = Session::new(1).unwrap();
    let mut events = session.subscribe();

    session.connect().unwrap();
    session.mark_connected().unwrap();
    session.disconnect().unwrap();

    assert!(events.recv().await.is_err());
    assert_eq!(
        events.recv().await.unwrap().to,
        ConnectionState::Disconnected
    );
}
