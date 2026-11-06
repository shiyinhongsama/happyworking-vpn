use std::net::Ipv4Addr;

use happyworking_vpn_core::{ErrorCode, VpnError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkOperation {
    CreateTun {
        name: String,
    },
    SetAddress {
        interface: String,
        address: Ipv4Addr,
        prefix: u8,
    },
    AddRoute {
        network: Ipv4Addr,
        prefix: u8,
        interface: String,
        gateway: Option<Ipv4Addr>,
    },
    RemoveRoute {
        network: Ipv4Addr,
        prefix: u8,
        interface: String,
        gateway: Option<Ipv4Addr>,
    },
    SetDns {
        interface: String,
        servers: Vec<Ipv4Addr>,
    },
}

pub trait NetworkBackend {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), VpnError>;
    fn rollback(&mut self, operation: &NetworkOperation) -> Result<(), VpnError>;
}

pub struct NetworkTransaction<B: NetworkBackend> {
    backend: B,
    applied: Vec<NetworkOperation>,
    finished: bool,
}

impl<B: NetworkBackend> NetworkTransaction<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            applied: Vec::new(),
            finished: false,
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn commit(mut self) -> B {
        self.finished = true;
        let this = std::mem::ManuallyDrop::new(self);
        // ManuallyDrop 阻止再次回滚，backend 只被移动这一次。
        unsafe { std::ptr::read(&this.backend) }
    }

    pub fn apply(&mut self, operation: NetworkOperation) -> Result<(), VpnError> {
        if self.finished {
            return Err(VpnError::new(
                ErrorCode::InvalidState,
                "网络事务已结束",
                &[],
            ));
        }

        self.backend.apply(&operation)?;
        self.applied.push(operation);
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<(), VpnError> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;

        let mut errors = Vec::new();
        for operation in self.applied.drain(..).rev() {
            if let Err(error) = self.backend.rollback(&operation) {
                errors.push(error.message().to_owned());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(VpnError::new(
                ErrorCode::NetworkUnavailable,
                format!("网络配置回滚失败：{}", errors.join("；")),
                &[],
            ))
        }
    }
}

impl<B: NetworkBackend> Drop for NetworkTransaction<B> {
    fn drop(&mut self) {
        let _ = self.rollback();
    }
}
