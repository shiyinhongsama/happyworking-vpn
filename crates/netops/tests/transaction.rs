use std::net::Ipv4Addr;

use happyworking_vpn_core::{ErrorCode, VpnError};
use happyworking_vpn_netops::{NetworkBackend, NetworkOperation, NetworkTransaction};

#[derive(Default)]
struct FakeBackend {
    applied: Vec<NetworkOperation>,
    rolled_back: Vec<NetworkOperation>,
    fail_application: Option<usize>,
}

impl NetworkBackend for FakeBackend {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), VpnError> {
        if self.fail_application == Some(self.applied.len()) {
            return Err(VpnError::new(
                ErrorCode::NetworkUnavailable,
                "模拟网络操作失败",
                &[],
            ));
        }
        self.applied.push(operation.clone());
        Ok(())
    }

    fn rollback(&mut self, operation: &NetworkOperation) -> Result<(), VpnError> {
        self.rolled_back.push(operation.clone());
        Ok(())
    }
}

fn create_tun() -> NetworkOperation {
    NetworkOperation::CreateTun {
        name: "omvpn0".to_owned(),
    }
}

fn set_address() -> NetworkOperation {
    NetworkOperation::SetAddress {
        interface: "omvpn0".to_owned(),
        address: Ipv4Addr::new(10, 0, 0, 2),
        prefix: 24,
    }
}

fn add_route() -> NetworkOperation {
    NetworkOperation::AddRoute {
        network: Ipv4Addr::new(172, 16, 0, 0),
        prefix: 16,
        interface: "omvpn0".to_owned(),
        gateway: None,
    }
}

#[test]
fn rolls_back_successful_operations_in_reverse_order() {
    let mut transaction = NetworkTransaction::new(FakeBackend::default());
    transaction.apply(create_tun()).unwrap();
    transaction.apply(set_address()).unwrap();
    transaction.apply(add_route()).unwrap();

    transaction.rollback().unwrap();

    assert_eq!(
        transaction.backend().rolled_back,
        [add_route(), set_address(), create_tun()]
    );
}

#[test]
fn a_failed_operation_is_not_recorded_as_applied() {
    let backend = FakeBackend {
        fail_application: Some(1),
        ..FakeBackend::default()
    };
    let mut transaction = NetworkTransaction::new(backend);
    transaction.apply(create_tun()).unwrap();

    assert!(transaction.apply(set_address()).is_err());
    transaction.rollback().unwrap();

    assert_eq!(transaction.backend().rolled_back, [create_tun()]);
}

#[test]
fn rollback_is_idempotent() {
    let mut transaction = NetworkTransaction::new(FakeBackend::default());
    transaction.apply(create_tun()).unwrap();
    transaction.rollback().unwrap();

    transaction.rollback().unwrap();

    assert_eq!(transaction.backend().rolled_back, [create_tun()]);
}

#[test]
fn drop_rolls_back_an_active_transaction() {
    struct SharedBackend {
        rolled_back: std::rc::Rc<std::cell::RefCell<Vec<NetworkOperation>>>,
    }

    impl NetworkBackend for SharedBackend {
        fn apply(&mut self, _operation: &NetworkOperation) -> Result<(), VpnError> {
            Ok(())
        }

        fn rollback(&mut self, operation: &NetworkOperation) -> Result<(), VpnError> {
            self.rolled_back.borrow_mut().push(operation.clone());
            Ok(())
        }
    }

    let rolled_back = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    {
        let mut transaction = NetworkTransaction::new(SharedBackend {
            rolled_back: std::rc::Rc::clone(&rolled_back),
        });
        transaction.apply(create_tun()).unwrap();
    }

    assert_eq!(*rolled_back.borrow(), [create_tun()]);
}

#[test]
fn commit_allows_ownership_transfer_without_rollback() {
    let mut transaction = NetworkTransaction::new(FakeBackend::default());
    transaction.apply(create_tun()).unwrap();

    let backend = transaction.commit();

    assert_eq!(backend.applied, [create_tun()]);
    assert_eq!(backend.rolled_back, []);
}
