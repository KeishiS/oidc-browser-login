//! 疑似IdPを使ったログイン全経路の試験。実IdPやコンテナーを必要としない。

use oidc_browser_login::{
    CallbackError, CallbackRejection, DiscoveryError, OidcLogin, OidcSettings,
    OidcSigningAlgorithm, UnixMillis,
};
use oidc_browser_login_testkit::{
    FakeIdp, FixedClock, IdTokenSpec, InMemoryLoginAttemptStore, SequenceEntropy,
};
use url::Url;

const CLIENT_ID: &str = "test-client";
const BASE_URL: &str = "https://app.example.test";

fn settings_for(idp: &FakeIdp) -> OidcSettings {
    OidcSettings::new(
        idp.issuer_url(),
        CLIENT_ID.into(),
        "test-client-secret".into(),
        BASE_URL,
    )
    .expect("valid settings")
}

/// 認可URLからstateとnonceを読み取る。実運用ではIdPがこの2値をcallbackとID tokenで返す。
fn state_and_nonce(authorize_url: &str) -> (String, String) {
    let url = Url::parse(authorize_url).expect("authorize URL");
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    (
        query.get("state").expect("state parameter").clone(),
        query.get("nonce").expect("nonce parameter").clone(),
    )
}

fn spec(algorithm: OidcSigningAlgorithm, nonce: &str, claims: serde_json::Value) -> IdTokenSpec {
    IdTokenSpec {
        algorithm,
        client_id: CLIENT_ID.into(),
        subject: "user-1".into(),
        nonce: nonce.into(),
        claims: claims.as_object().expect("claims object").clone(),
    }
}

#[tokio::test]
async fn completes_a_login_and_reads_groups_signed_with_es256() {
    let idp = FakeIdp::start().await;
    let login = OidcLogin::discover(&settings_for(&idp))
        .await
        .expect("discovery");
    let store = InMemoryLoginAttemptStore::default();
    let clock = FixedClock(UnixMillis::new(1_000));
    let entropy = SequenceEntropy::new(["state", "nonce", "verifier"]);

    let authorize_url = login
        .begin_login(&store, &entropy, &clock)
        .await
        .expect("begin login");
    let (state, nonce) = state_and_nonce(&authorize_url);
    idp.respond_token_exchange(idp.mint_id_token(&spec(
        OidcSigningAlgorithm::EcdsaP256Sha256,
        &nonce,
        serde_json::json!({"groups": ["server-users", "editors"]}),
    )))
    .await;

    let identity = login
        .complete_login(&store, &clock, "test-code", &state)
        .await
        .expect("complete login");
    assert_eq!(identity.issuer, idp.issuer_url());
    assert_eq!(identity.subject, "user-1");
    assert!(identity.groups.contains("server-users"));
    assert!(!identity.groups.contains("strangers"));
}

#[tokio::test]
async fn rejects_an_id_token_with_a_mismatched_nonce() {
    let idp = FakeIdp::start().await;
    let login = OidcLogin::discover(&settings_for(&idp))
        .await
        .expect("discovery");
    let store = InMemoryLoginAttemptStore::default();
    let clock = FixedClock(UnixMillis::new(1_000));
    let entropy = SequenceEntropy::new(["state", "nonce", "verifier"]);

    let authorize_url = login
        .begin_login(&store, &entropy, &clock)
        .await
        .expect("begin login");
    let (state, _) = state_and_nonce(&authorize_url);
    idp.respond_token_exchange(idp.mint_id_token(&spec(
        OidcSigningAlgorithm::EcdsaP256Sha256,
        "another-nonce",
        serde_json::json!({"groups": ["server-users"]}),
    )))
    .await;

    assert_eq!(
        login
            .complete_login(&store, &clock, "test-code", &state)
            .await,
        Err(CallbackError::Rejected(CallbackRejection::Claims))
    );
}

#[tokio::test]
async fn rejects_an_unknown_state() {
    let idp = FakeIdp::start().await;
    let login = OidcLogin::discover(&settings_for(&idp))
        .await
        .expect("discovery");
    let store = InMemoryLoginAttemptStore::default();
    let clock = FixedClock(UnixMillis::new(1_000));

    assert_eq!(
        login
            .complete_login(&store, &clock, "test-code", "forged-state")
            .await,
        Err(CallbackError::Rejected(CallbackRejection::State))
    );
}

/// RS256は既定で拒否し、明示的に許可した場合だけ検証に使う。
#[tokio::test]
async fn rs256_requires_an_explicit_opt_in() {
    let idp = FakeIdp::start_with_algorithms(&[OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256]).await;

    // 既定(ES256のみ)では、RS256しか広告しないIdPとのdiscoveryを拒否する。
    assert_eq!(
        OidcLogin::discover(&settings_for(&idp)).await.err(),
        Some(DiscoveryError::Discovery)
    );

    let settings = settings_for(&idp)
        .with_allowed_algorithms(vec![
            OidcSigningAlgorithm::EcdsaP256Sha256,
            OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        ])
        .expect("algorithms");
    let login = OidcLogin::discover(&settings).await.expect("discovery");
    let store = InMemoryLoginAttemptStore::default();
    let clock = FixedClock(UnixMillis::new(1_000));
    let entropy = SequenceEntropy::new(["state", "nonce", "verifier"]);

    let authorize_url = login
        .begin_login(&store, &entropy, &clock)
        .await
        .expect("begin login");
    let (state, nonce) = state_and_nonce(&authorize_url);
    idp.respond_token_exchange(idp.mint_id_token(&spec(
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        &nonce,
        serde_json::json!({"groups": ["server-users"]}),
    )))
    .await;

    let identity = login
        .complete_login(&store, &clock, "test-code", &state)
        .await
        .expect("complete login");
    assert!(identity.groups.contains("server-users"));
}

/// claim名は設定でき、emailを使う場合はemail_verifiedがtrueであることも要求する。
#[tokio::test]
async fn reads_a_configured_email_claim_only_when_verified() {
    let idp = FakeIdp::start().await;
    let settings = settings_for(&idp)
        .with_group_claim("email".into())
        .expect("claim name");
    let login = OidcLogin::discover(&settings).await.expect("discovery");
    let clock = FixedClock(UnixMillis::new(1_000));

    let store = InMemoryLoginAttemptStore::default();
    let entropy = SequenceEntropy::new(["state", "nonce", "verifier"]);
    let authorize_url = login
        .begin_login(&store, &entropy, &clock)
        .await
        .expect("begin login");
    let (state, nonce) = state_and_nonce(&authorize_url);
    idp.respond_token_exchange(idp.mint_id_token(&spec(
        OidcSigningAlgorithm::EcdsaP256Sha256,
        &nonce,
        serde_json::json!({"email": "user@example.com", "email_verified": true}),
    )))
    .await;
    let identity = login
        .complete_login(&store, &clock, "test-code", &state)
        .await
        .expect("complete login");
    assert!(identity.groups.contains("user@example.com"));

    // email_verifiedがないID tokenは拒否する。
    let store = InMemoryLoginAttemptStore::default();
    let entropy = SequenceEntropy::new(["state-2", "nonce-2", "verifier-2"]);
    let authorize_url = login
        .begin_login(&store, &entropy, &clock)
        .await
        .expect("begin login");
    let (state, nonce) = state_and_nonce(&authorize_url);
    idp.respond_token_exchange(idp.mint_id_token(&spec(
        OidcSigningAlgorithm::EcdsaP256Sha256,
        &nonce,
        serde_json::json!({"email": "user@example.com"}),
    )))
    .await;
    assert_eq!(
        login
            .complete_login(&store, &clock, "test-code", &state)
            .await,
        Err(CallbackError::Rejected(CallbackRejection::Groups))
    );
}

/// claimが数値など文字列以外の型の場合はfail closedで拒否する。
#[tokio::test]
async fn rejects_a_claim_with_an_unexpected_type() {
    let idp = FakeIdp::start().await;
    let login = OidcLogin::discover(&settings_for(&idp))
        .await
        .expect("discovery");
    let store = InMemoryLoginAttemptStore::default();
    let clock = FixedClock(UnixMillis::new(1_000));
    let entropy = SequenceEntropy::new(["state", "nonce", "verifier"]);

    let authorize_url = login
        .begin_login(&store, &entropy, &clock)
        .await
        .expect("begin login");
    let (state, nonce) = state_and_nonce(&authorize_url);
    idp.respond_token_exchange(idp.mint_id_token(&spec(
        OidcSigningAlgorithm::EcdsaP256Sha256,
        &nonce,
        serde_json::json!({"groups": 42}),
    )))
    .await;

    assert_eq!(
        login
            .complete_login(&store, &clock, "test-code", &state)
            .await,
        Err(CallbackError::Rejected(CallbackRejection::Groups))
    );
}

/// 件数上限を超えるgroupsはfail closedで拒否する。
#[tokio::test]
async fn rejects_groups_beyond_the_fail_closed_limit() {
    let idp = FakeIdp::start().await;
    let login = OidcLogin::discover(&settings_for(&idp))
        .await
        .expect("discovery");
    let store = InMemoryLoginAttemptStore::default();
    let clock = FixedClock(UnixMillis::new(1_000));
    let entropy = SequenceEntropy::new(["state", "nonce", "verifier"]);

    let authorize_url = login
        .begin_login(&store, &entropy, &clock)
        .await
        .expect("begin login");
    let (state, nonce) = state_and_nonce(&authorize_url);
    let groups: Vec<String> = (0..=oidc_browser_login::MAX_GROUPS_PER_ID_TOKEN)
        .map(|index| format!("group-{index}"))
        .collect();
    idp.respond_token_exchange(idp.mint_id_token(&spec(
        OidcSigningAlgorithm::EcdsaP256Sha256,
        &nonce,
        serde_json::json!({"groups": groups}),
    )))
    .await;

    assert_eq!(
        login
            .complete_login(&store, &clock, "test-code", &state)
            .await,
        Err(CallbackError::Rejected(CallbackRejection::Groups))
    );
}
