use std::sync::Mutex;

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::{ConnectionState, ErrorCode, StateChange, VpnError};

pub struct Session {
    state: Mutex<ConnectionState>,
    events: broadcast::Sender<StateChange>,
    cancellation: CancellationToken,
}

impl Session {
    pub fn new(event_capacity: usize) -> Result<Self, VpnError> {
        if event_capacity == 0 {
            return Err(VpnError::new(
                ErrorCode::InvalidConfiguration,
                "事件通道容量必须大于 0",
                &[],
            ));
        }

        let (events, _) = broadcast::channel(event_capacity);
        Ok(Self {
            state: Mutex::new(ConnectionState::Disconnected),
            events,
            cancellation: CancellationToken::new(),
        })
    }

    pub fn state(&self) -> ConnectionState {
        *self.lock_state()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<StateChange> {
        self.events.subscribe()
    }

    pub fn connect(&self) -> Result<(), VpnError> {
        self.transition(ConnectionState::Connecting).map(|_| ())
    }

    pub fn mark_connected(&self) -> Result<(), VpnError> {
        self.transition(ConnectionState::Connected).map(|_| ())
    }

    /// 隧道意外中断后进入自动恢复过程。
    pub fn mark_reconnecting(&self) -> Result<(), VpnError> {
        self.transition(ConnectionState::Reconnecting).map(|_| ())
    }

    pub fn fail(&self) -> Result<(), VpnError> {
        self.transition(ConnectionState::Failed).map(|_| ())
    }

    pub fn disconnect(&self) -> Result<(), VpnError> {
        match self.state() {
            ConnectionState::Disconnected => return Ok(()),
            ConnectionState::Connecting
            | ConnectionState::Connected
            | ConnectionState::Reconnecting => {
                self.transition(ConnectionState::Disconnecting)?;
            }
            ConnectionState::Failed | ConnectionState::Disconnecting => {}
        }
        self.transition(ConnectionState::Disconnected).map(|_| ())
    }

    pub fn cancel(&self) -> Result<(), VpnError> {
        self.cancellation.cancel();
        self.disconnect()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    fn transition(&self, to: ConnectionState) -> Result<StateChange, VpnError> {
        let from = self.state();
        if !is_allowed(from, to) {
            return Err(VpnError::new(
                ErrorCode::InvalidState,
                format!("不能从 {from:?} 转换到 {to:?}"),
                &[],
            ));
        }

        let change = StateChange { from, to };
        *self.lock_state() = to;
        let _ = self.events.send(change);
        Ok(change)
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ConnectionState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn is_allowed(from: ConnectionState, to: ConnectionState) -> bool {
    matches!(
        (from, to),
        (ConnectionState::Disconnected, ConnectionState::Connecting)
            | (ConnectionState::Connecting, ConnectionState::Connected)
            | (ConnectionState::Connecting, ConnectionState::Disconnecting)
            | (ConnectionState::Connecting, ConnectionState::Failed)
            | (ConnectionState::Connecting, ConnectionState::Reconnecting)
            | (ConnectionState::Connected, ConnectionState::Disconnecting)
            | (ConnectionState::Connected, ConnectionState::Failed)
            | (ConnectionState::Connected, ConnectionState::Reconnecting)
            | (
                ConnectionState::Disconnecting,
                ConnectionState::Disconnected
            )
            | (ConnectionState::Disconnecting, ConnectionState::Failed)
            | (ConnectionState::Reconnecting, ConnectionState::Connected)
            | (
                ConnectionState::Reconnecting,
                ConnectionState::Disconnecting
            )
            | (ConnectionState::Reconnecting, ConnectionState::Failed)
            | (ConnectionState::Failed, ConnectionState::Connecting)
            | (ConnectionState::Failed, ConnectionState::Disconnected)
    )
}
