use std::time::Duration;

use happyworking_vpn_core::{ErrorCode, VpnError};
use tokio_util::sync::CancellationToken;

pub struct ReconnectBackoff {
    base: Duration,
    maximum: Duration,
    attempt: u32,
}

impl ReconnectBackoff {
    pub fn new(base_milliseconds: u64, maximum_milliseconds: u64) -> Result<Self, VpnError> {
        if base_milliseconds == 0 || maximum_milliseconds < base_milliseconds {
            return Err(VpnError::new(
                ErrorCode::InvalidConfiguration,
                "重连退避时间无效",
                &[],
            ));
        }
        Ok(Self {
            base: Duration::from_millis(base_milliseconds),
            maximum: Duration::from_millis(maximum_milliseconds),
            attempt: 0,
        })
    }

    pub fn next_delay(&mut self) -> Duration {
        let factor = 1_u64.checked_shl(self.attempt).unwrap_or(u64::MAX);
        self.attempt = self.attempt.saturating_add(1);
        self.base
            .saturating_mul(factor.min(u32::MAX as u64) as u32)
            .min(self.maximum)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

pub async fn wait_for_reconnect(
    backoff: &mut ReconnectBackoff,
    cancellation: CancellationToken,
) -> Result<(), VpnError> {
    tokio::select! {
        () = tokio::time::sleep(backoff.next_delay()) => Ok(()),
        () = cancellation.cancelled() => {
            Err(VpnError::new(ErrorCode::Cancelled, "重连已取消", &[]))
        }
    }
}
