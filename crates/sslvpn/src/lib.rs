mod auth;
mod codec;
mod http;
mod net;
mod tls;
mod tunnel;

pub use tunnel::{
    DataPlaneOptions, FrameDecoder, ReconnectBackoff, TunnelConfig, TunnelConnection, TunnelFrame,
    TunnelRoute, encode_ip_frame, forward_connection, forward_streams, heartbeat_frame,
    negotiate_v3, negotiate_v7, wait_for_reconnect,
};

pub use auth::{
    AuthOutcome, AuthSession, Challenge, GatewayCapabilities, V3LoginInput, V3LoginOutcome,
    V3OldLogin, V3Parameters, V3Session, V7Credentials, V7SecondAuthInput, build_v3_kick_request,
    build_v3_login_body, build_v3_login_request, build_v3_logout_request,
    build_v3_old_user_request, build_v7_image_request, build_v7_login_body,
    build_v7_login_body_with_code, build_v7_login_request, build_v7_login_request_with_code,
    build_v7_logout_request, build_v7_second_login_body, build_v7_second_login_request,
    challenge_v7, check_online_v7, discover, get_v7_verify_image, login_v3, login_v7, logout_v3,
    logout_v7, parse_v3_login_response, parse_v3_old_login, parse_v3_parameters,
    parse_v7_login_response, validate_gateway_path,
};
pub use codec::{private_content, url_encode};
pub use http::{HttpRequest, HttpResponse};
pub use net::local_mac_address;
pub use tls::{ClientIdentity, PeerCertificate, TlsOptions, probe_certificate};
