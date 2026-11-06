mod discovery;
mod v3;
mod v7;

pub use discovery::{GatewayCapabilities, discover, validate_gateway_path};
pub use v3::{
    V3LoginInput, V3LoginOutcome, V3OldLogin, V3Parameters, V3Session, build_v3_kick_request,
    build_v3_login_body, build_v3_login_request, build_v3_logout_request,
    build_v3_old_user_request, login_v3, logout_v3, parse_v3_login_response, parse_v3_old_login,
    parse_v3_parameters,
};
pub use v7::{
    AuthOutcome, AuthSession, Challenge, V7Credentials, V7SecondAuthInput, build_v7_image_request,
    build_v7_login_body, build_v7_login_body_with_code, build_v7_login_request,
    build_v7_login_request_with_code, build_v7_logout_request, build_v7_second_login_body,
    build_v7_second_login_request, challenge_v7, check_online_v7, get_v7_verify_image, login_v7,
    logout_v7, parse_v7_login_response,
};
