#![cfg(feature = "ureq")]

//! A `ureq` agent logs in to an origin server that answers `401`, against loopback stand-ins.

mod support;

use coqui_syshttp::client::{AgentBuilder, OriginAgent};
use coqui_syshttp::{Credentials, Environment, OriginAuth, Resolver};
use support::login_origin::{Demand, LoginOrigin};
use ureq::http::{Request, header};

fn agent(status_as_error: bool) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(status_as_error)
        .build();
    AgentBuilder::new()
        .resolver(
            Resolver::builder()
                .environment(Environment::default())
                .system(false)
                .build(),
        )
        .config(config)
        .build()
        .unwrap()
}

fn basic(user: &str, password: &str) -> OriginAuth {
    OriginAuth::builder()
        .basic(["127.0.0.1"], Credentials::new(user, password))
        .build()
        .unwrap()
}

fn get(url: &str) -> Request<Vec<u8>> {
    Request::get(url).body(Vec::new()).unwrap()
}

#[test]
fn a_basic_challenge_is_answered_on_the_same_connection() {
    let origin = LoginOrigin::start(Demand::Basic("ada", "s3cret"));
    let client = OriginAgent::new(agent(true), basic("ada", "s3cret"));
    let mut response = client
        .run(get(&origin.url("127.0.0.1", "/ews")))
        .expect("a login");
    assert_eq!(response.body_mut().read_to_string().unwrap(), "welcome");

    let log = origin.log();
    assert_eq!(log.len(), 2, "{log:?}");
    assert_eq!(log[0].authorization, None);
    assert_eq!(
        log[1].authorization.as_deref(),
        Some("Basic YWRhOnMzY3JldA==")
    );
    assert_eq!(log[0].connection, log[1].connection);
}

#[test]
fn credentials_the_server_refuses_end_with_the_401_and_are_sent_once() {
    let origin = LoginOrigin::start(Demand::Basic("ada", "s3cret"));
    let client = OriginAgent::new(agent(true), basic("ada", "wrong"));
    let result = client.run(get(&origin.url("127.0.0.1", "/")));
    assert!(matches!(result, Err(ureq::Error::StatusCode(401))));
    assert_eq!(origin.log().len(), 2);
    let kept = OriginAgent::new(agent(false), basic("ada", "wrong"));
    let result = kept.run(get(&origin.url("127.0.0.1", "/")));
    assert_eq!(result.unwrap().status().as_u16(), 401);
}

#[test]
fn a_server_without_a_rule_is_not_answered_and_gets_no_credentials() {
    let origin = LoginOrigin::start(Demand::Basic("ada", "s3cret"));
    let other = OriginAuth::builder()
        .basic(["mail.corp.example"], Credentials::new("ada", "s3cret"))
        .build()
        .unwrap();
    let client = OriginAgent::new(agent(true), other);
    let result = client.run(get(&origin.url("127.0.0.1", "/")));
    assert!(matches!(result, Err(ureq::Error::StatusCode(401))));
    let log = origin.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].authorization, None);
}

#[test]
fn a_request_with_its_own_authorization_is_sent_as_it_is() {
    let origin = LoginOrigin::start(Demand::Basic("ada", "s3cret"));
    let client = OriginAgent::new(agent(true), basic("ada", "s3cret"));
    let request = Request::get(origin.url("127.0.0.1", "/"))
        .header(header::AUTHORIZATION, "Bearer abc")
        .body(Vec::new())
        .unwrap();
    assert!(matches!(
        client.run(request),
        Err(ureq::Error::StatusCode(401))
    ));
    let log = origin.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].authorization.as_deref(), Some("Bearer abc"));
}

#[test]
fn a_post_body_is_sent_again_with_the_login() {
    let origin = LoginOrigin::start(Demand::Basic("ada", "s3cret"));
    let client = OriginAgent::new(agent(true), basic("ada", "s3cret"));
    let request = Request::post(origin.url("127.0.0.1", "/ews"))
        .header(header::CONTENT_TYPE, "text/xml")
        .body(b"<soap/>".to_vec())
        .unwrap();
    let response = client.run(request).expect("a login");
    assert_eq!(response.status().as_u16(), 200);
    let log = origin.log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].method, "POST");
    assert_eq!((log[0].body_length, log[1].body_length), (7, 7));
}

#[test]
fn a_401_from_another_host_after_a_redirect_is_not_answered() {
    let target = LoginOrigin::start(Demand::Basic("ada", "s3cret"));
    let first = LoginOrigin::start(Demand::Redirect(target.url("localhost", "/")));
    let client = OriginAgent::new(agent(true), basic("ada", "s3cret"));
    let result = client.run(get(&first.url("127.0.0.1", "/")));
    assert!(matches!(result, Err(ureq::Error::StatusCode(401))));
    let log = target.log();
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].authorization, None);
}

#[cfg(all(windows, feature = "negotiate"))]
mod security {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    fn negotiate() -> OriginAuth {
        OriginAuth::builder()
            .negotiate(["127.0.0.1"])
            .build()
            .unwrap()
    }

    fn token_of(authorization: &str) -> Vec<u8> {
        let (_, token) = authorization.split_once(' ').unwrap();
        STANDARD.decode(token).unwrap()
    }

    #[test]
    fn negotiate_logs_in_with_the_logon_session_on_one_connection() {
        let origin = LoginOrigin::start(Demand::Security("Negotiate"));
        let client = OriginAgent::new(agent(true), negotiate());
        let response = client
            .run(get(&origin.url("127.0.0.1", "/ews")))
            .expect("a login");
        assert_eq!(response.status().as_u16(), 200);

        let log = origin.log();
        assert!(log.len() >= 2, "{log:?}");
        assert_eq!(log[0].authorization, None);
        let authorization = log[1].authorization.as_deref().expect("a token");
        assert!(authorization.starts_with("Negotiate "), "{authorization}");
        // The token is SPNEGO (an ASN.1 application tag) or a bare NTLM message.
        let token = token_of(authorization);
        assert!(
            token.first() == Some(&0x60) || token.starts_with(b"NTLMSSP\0"),
            "{token:02x?}"
        );
        assert!(
            log.iter()
                .all(|entry| entry.connection == log[0].connection)
        );
        let users = origin.users();
        assert_eq!(users.len(), 1);
        let account = std::env::var("USERNAME").unwrap();
        assert!(users[0].to_lowercase().ends_with(&account.to_lowercase()));
    }

    #[test]
    fn ntlm_opens_with_a_body_less_message_and_sends_the_body_with_the_last() {
        let origin = LoginOrigin::start(Demand::Security("NTLM"));
        let client = OriginAgent::new(agent(true), negotiate());
        let request = Request::post(origin.url("127.0.0.1", "/ews"))
            .body(b"<soap>0123456789</soap>".to_vec())
            .unwrap();
        let response = client.run(request).expect("a login");
        assert_eq!(response.status().as_u16(), 200);

        let log = origin.log();
        assert_eq!(log.len(), 3, "{log:?}");
        let second = log[1].authorization.as_deref().unwrap();
        assert!(second.starts_with("NTLM "));
        assert!(token_of(second).starts_with(b"NTLMSSP\0"));
        assert_eq!(
            log.iter()
                .map(|entry| entry.body_length)
                .collect::<Vec<_>>(),
            [23, 0, 23]
        );
        assert!(
            log.iter()
                .all(|entry| entry.connection == log[0].connection)
        );
    }

    #[test]
    fn a_server_offering_only_basic_to_a_negotiate_rule_is_left_at_its_401() {
        let origin = LoginOrigin::start(Demand::Basic("ada", "s3cret"));
        let client = OriginAgent::new(agent(true), negotiate());
        assert!(matches!(
            client.run(get(&origin.url("127.0.0.1", "/"))),
            Err(ureq::Error::StatusCode(401))
        ));
        assert_eq!(origin.log().len(), 1);
    }
}
