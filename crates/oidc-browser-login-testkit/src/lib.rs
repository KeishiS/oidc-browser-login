//! `oidc-browser-login`の利用側が使う試験用部品。
//!
//! 提供するのは次の3種類です。いずれも試験専用であり、production依存に含めないでください。
//!
//! - [`FakeIdp`][]: wiremockで動く疑似OIDC IdP。discovery、JWKS、token endpointを提供し、
//!   ES256とRS256で署名したID tokenを発行する。実IdPなしでログインの全経路を試験できる。
//! - [`InMemoryLoginAttemptStore`]、[`FixedClock`]、[`SequenceEntropy`]: 各portの試験実装。
//! - [`check_login_attempt_store_contract`][]: [`LoginAttemptStore`]実装が満たすべき契約の試験。
//!   利用側は自前のadapter(SQLiteやPostgreSQLなど)をこの関数へ渡して交換可能性を確かめる。

#[cfg(feature = "session")]
pub mod session;
#[cfg(feature = "session")]
pub use session::{InMemoryWebSessionStore, check_web_session_store_contract};

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use oidc_browser_login::{
    Clock, Entropy, LoginAttempt, LoginAttemptStore, OidcSigningAlgorithm, UnixMillis,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// 疑似IdPの署名鍵。試験専用に公開している鍵であり、secretではない。実配備で使わないこと。
const ES256_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQ3PkiDHS2RvGb10H
ugpRlXD6Pw1/3iyxDHIvEbmr2eChRANCAAR+HyStGrgeTZxis0jxttcm8q3mph6I
ZUGYHXG2OW4lUY+JFT2QJQn1IPkqFA90H158+6TKHhSSExXnUALgLcsH
-----END PRIVATE KEY-----
";

/// 疑似IdPの署名鍵。試験専用に公開している鍵であり、secretではない。実配備で使わないこと。
const RS256_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDiSZFH1oqzW02q
nKcvPfMnNMc7y97IdCk1F/SOAFL2wGVvNDnsAznHjdzInYd5Pg4R6ijzTzE07gyB
my0+67NTSkLKZJR9Mqzo9xH//6LPitDN1nQwuwgKet+v9+RRczltzG4kz3tavJYy
H2VZG+D8/yqE/viNRvkN0cz0PG/OID8t+7waQAFRmEosuxp0Zg62Hbo3HoF7Laqp
ctJ0OwLljoH4wfeB2AvFlZ8aIqoLErFemeGizRYz+g04n52XNlRh7YT7/lzT+w7a
ojqtgdpIX9kQ3mm1QhhTBATKk4U1Mlqw0RToZxOCNpEps22N+w6Arr1dMIJypPFR
jLMb6xyjAgMBAAECggEAN1zMYIkK0irKa6178cD0VmlBPU35qY1R7512xa8qnRgh
OP3MFgQMBNieZa600GLwSk3ByxVa8pozERqIDVbZPs1yXdYRxje5uh2Il9tRV/mc
cF/BeZKouveo9oJtp8fLCyPy5qqkgWSWUpj/0LdTalJ7cqJ26QmuMUVdIXwP1pvz
U1YjLiiJWNEcjWVXEdywt0j87p41GCdwz4LKG6Dit0X7YVNeGIE6Vj/O8im6uhKr
7vGruCuEVS+fQ7pSRdfnTg+tsCsR5MmgLiZXUr0GS15V+rU+2Rg/+N4sBOiBc83u
PVbPbRCiPh9j+DTnlUuWAD6zbU0ZDJDUSK75pn+V4QKBgQDxjgpFLroSqkVLwYre
w+8j43jU6SKKeQ3tirBhh+yAOm5kA3yl3edHNUbqxFLyCof/XIAGq19UM1JayvNi
BK3sWEwzlmjGflM7FSX/XZKPRVhht0Ou5CZfv89vcPBDJ8sPjAMHM8cIDy7k4xKO
VTWehI2YcpyRG9nZsaYWkmp72wKBgQDv0cxBXXYqaLKsL3HxLCQ8WJJ/1J+3rluA
FSeDLnx0jUopRetgE2T8xcqdL1KH0dWsAtd9YD4C4KC6hILI5sRbTBjgO1N0bMg5
EFNuSmepJDqBEpmF/uGmvTGhqKElDZKwSNbrIAMTzbDxm2TwTWF4GS0wF7CMX/3h
/IQQRIJg2QKBgCRpa+Tn2UatAgscXqmb0XWQeYtmpT1IaDARgusAyUa/CBrtZ6G9
JHrYbhs/gt1Xdw6oS+g1dwZDQjvLcgqpd+ozmTEBkEOzkSpL0tF+snQEWQFJ1dsM
KzitukArPxxwaCysx1wTkwIE/+Wi0Q5Bi/acNpfvVuiM0Tb+j3HBmmmXAoGBAIik
VCoGM5bUUsFywww0J21O1iIJpvtEWBQxeXLwIK9T9aZwlT0Hr+mqVNicpvyGHaXF
dLyWAp8nF81ORSps+gI+6ImSo+lZNff1imPz9v5TixYR3/GOGUok0EuYxkBTbHoO
9o2/jqFQ+HmhHbEhleCVD78wMEK7Su/hLeoK7vJ5AoGBAIlteC3982WE2cAg8AvW
Evnj6gFOHNAbD/yK653vRE5Coqx0nTDvVUNnVFl2m70N3ica0QEO9SfZBb6iYH8A
9mnNWHakKz88bg7o15RahBgrp8fI/mw0y8pAvgWrwqo6zTbxX7DH17LtKnuTOmax
37MHryXW89lSEO+Y3MdKJLM2
-----END PRIVATE KEY-----
";

/// 上記の署名鍵に対応する公開JWKS。
const JWKS_JSON: &str = r#"{"keys":[
{"kty":"EC","x":"fh8krRq4Hk2cYrNI8bbXJvKt5qYeiGVBmB1xtjluJVE","y":"j4kVPZAlCfUg-SoUD3QfXnz7pMoeFJITFedQAuAtywc","crv":"P-256","kid":"test-es256","alg":"ES256","use":"sig"},
{"kty":"RSA","n":"4kmRR9aKs1tNqpynLz3zJzTHO8veyHQpNRf0jgBS9sBlbzQ57AM5x43cyJ2HeT4OEeoo808xNO4MgZstPuuzU0pCymSUfTKs6PcR__-iz4rQzdZ0MLsICnrfr_fkUXM5bcxuJM97WryWMh9lWRvg_P8qhP74jUb5DdHM9DxvziA_Lfu8GkABUZhKLLsadGYOth26Nx6Bey2qqXLSdDsC5Y6B-MH3gdgLxZWfGiKqCxKxXpnhos0WM_oNOJ-dlzZUYe2E-_5c0_sO2qI6rYHaSF_ZEN5ptUIYUwQEypOFNTJasNEU6GcTgjaRKbNtjfsOgK69XTCCcqTxUYyzG-scow","e":"AQAB","kid":"test-rs256","alg":"RS256","use":"sig"}
]}"#;

fn algorithm_name(algorithm: &OidcSigningAlgorithm) -> &'static str {
    match algorithm {
        OidcSigningAlgorithm::EcdsaP256Sha256 => "ES256",
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256 => "RS256",
        _ => panic!("FakeIdp supports only ES256 and RS256"),
    }
}

/// wiremockで動く疑似OIDC IdP。
///
/// discovery文書、JWKS、token endpointを同一プロセス内のHTTPで提供する。issuerはloopbackの
/// HTTP URLになるため、`OidcSettings`のloopback例外で受理される。
pub struct FakeIdp {
    server: MockServer,
}

/// [`FakeIdp::respond_token_exchange`]が発行するID tokenの内容。
pub struct IdTokenSpec {
    pub algorithm: OidcSigningAlgorithm,
    pub client_id: String,
    pub subject: String,
    pub nonce: String,
    /// 標準claimに加えて埋め込む任意のclaim(所属groupsなど)。
    pub claims: serde_json::Map<String, serde_json::Value>,
}

impl FakeIdp {
    /// ES256だけを広告する疑似IdPを起動する。
    pub async fn start() -> Self {
        Self::start_with_algorithms(&[OidcSigningAlgorithm::EcdsaP256Sha256]).await
    }

    /// 広告する署名アルゴリズムを指定して起動する。ES256とRS256だけに対応する。
    pub async fn start_with_algorithms(algorithms: &[OidcSigningAlgorithm]) -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let advertised: Vec<&str> = algorithms
            .iter()
            .map(|algorithm| algorithm_name(algorithm))
            .collect();
        let discovery = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
            "token_endpoint": format!("{issuer}/oauth2/token"),
            "jwks_uri": format!("{issuer}/oauth2/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": advertised,
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
            .mount(&server)
            .await;
        let jwks: serde_json::Value = serde_json::from_str(JWKS_JSON).expect("static JWKS");
        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;
        Self { server }
    }

    /// このIdPのissuer URL。`OidcSettings::new`へそのまま渡せる。
    pub fn issuer_url(&self) -> String {
        self.server.uri()
    }

    /// 指定した内容で署名したID tokenを発行する。
    ///
    /// 発行時刻は現在時刻、有効期間は1時間とする。署名鍵はJWKSと対応する試験用の静的鍵。
    pub fn mint_id_token(&self, spec: &IdTokenSpec) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time")
            .as_secs();
        let mut claims = spec.claims.clone();
        claims.insert("iss".into(), self.server.uri().into());
        claims.insert("aud".into(), spec.client_id.clone().into());
        claims.insert("sub".into(), spec.subject.clone().into());
        claims.insert("nonce".into(), spec.nonce.clone().into());
        claims.insert("iat".into(), now.into());
        claims.insert("exp".into(), (now + 3_600).into());
        let (algorithm, kid, key) = match &spec.algorithm {
            OidcSigningAlgorithm::EcdsaP256Sha256 => (
                jsonwebtoken::Algorithm::ES256,
                "test-es256",
                jsonwebtoken::EncodingKey::from_ec_pem(ES256_SIGNING_KEY_PEM.as_bytes()),
            ),
            OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256 => (
                jsonwebtoken::Algorithm::RS256,
                "test-rs256",
                jsonwebtoken::EncodingKey::from_rsa_pem(RS256_SIGNING_KEY_PEM.as_bytes()),
            ),
            _ => panic!("FakeIdp supports only ES256 and RS256"),
        };
        let mut header = jsonwebtoken::Header::new(algorithm);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, &claims, &key.expect("test signing key"))
            .expect("sign test ID token")
    }

    /// token endpointが次のcode交換へ返すID tokenを設定する。
    pub async fn respond_token_exchange(&self, id_token: String) {
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 3_600,
                "id_token": id_token,
            })))
            // 1回で消費するmockにする。複数回呼ぶ試験では、交換のたびに設定し直す。
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }
}

/// 固定時刻を返す[`Clock`]の試験実装。
pub struct FixedClock(pub UnixMillis);

impl Clock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

/// 与えた値を順に返す[`Entropy`]の試験実装。値が尽きるとpanicする。
///
/// `begin_login`はstate、nonce、PKCE verifierの順に3回`opaque_token`を呼ぶ。PKCE verifierは
/// 43文字以上が必要なため、短い名前は自動で43文字まで`-`で埋める。
pub struct SequenceEntropy {
    tokens: Mutex<Vec<String>>,
}

impl SequenceEntropy {
    pub fn new<I, T>(tokens: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let mut tokens: Vec<String> = tokens
            .into_iter()
            .map(|token| {
                let mut token = token.into();
                while token.len() < 43 {
                    token.push('-');
                }
                token
            })
            .collect();
        tokens.reverse();
        Self {
            tokens: Mutex::new(tokens),
        }
    }
}

impl Entropy for SequenceEntropy {
    fn opaque_token(&self) -> String {
        self.tokens
            .lock()
            .expect("sequence entropy lock")
            .pop()
            .expect("SequenceEntropy ran out of tokens")
    }
}

/// [`LoginAttemptStore`]契約のメモリー実装。契約試験の参照実装でもある。
#[derive(Default)]
pub struct InMemoryLoginAttemptStore {
    attempts: Mutex<HashMap<String, LoginAttempt>>,
}

/// [`InMemoryLoginAttemptStore`]は失敗しないため、このerrorは発生しない。
#[derive(Debug)]
pub struct Never;

impl std::fmt::Display for Never {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("in-memory store cannot fail")
    }
}

impl std::error::Error for Never {}

impl LoginAttemptStore for InMemoryLoginAttemptStore {
    type Error = Never;

    async fn issue(&self, attempt: LoginAttempt, now: UnixMillis) -> Result<(), Self::Error> {
        let mut attempts = self.attempts.lock().expect("attempt store lock");
        attempts.retain(|_, pending| pending.expires_at > now);
        attempts.insert(attempt.state.clone(), attempt);
        Ok(())
    }

    async fn consume(
        &self,
        state: String,
        now: UnixMillis,
    ) -> Result<Option<LoginAttempt>, Self::Error> {
        let mut attempts = self.attempts.lock().expect("attempt store lock");
        Ok(attempts
            .remove(&state)
            .filter(|attempt| attempt.expires_at > now))
    }
}

/// [`LoginAttemptStore`]実装が満たすべき契約を確かめる。
///
/// `new_store`は呼出しごとに空のstoreを返すこと。確かめる契約は次の4点。
///
/// - 保存した試行は、同じstateの`consume`が内容ごと返す
/// - 同じstateの2回目の`consume`は`None`を返す(一度きり)
/// - 未知のstateは`None`を返す
/// - `expires_at <= now`の試行は期限切れとして`None`を返す
pub async fn check_login_attempt_store_contract<S, F, Fut>(new_store: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
    S: LoginAttemptStore,
{
    let attempt = |state: &str, expires_at: i64| LoginAttempt {
        state: state.into(),
        nonce: format!("{state}-nonce"),
        pkce_verifier: format!("{state}-verifier"),
        expires_at: UnixMillis::new(expires_at),
    };
    let now = UnixMillis::new(1_000);

    let store = new_store().await;
    store
        .issue(attempt("state-a", 2_000), now)
        .await
        .unwrap_or_else(|_| panic!("issue must succeed"));
    let consumed = store
        .consume("state-a".into(), now)
        .await
        .unwrap_or_else(|_| panic!("consume must succeed"))
        .expect("issued attempt must be returned once");
    assert_eq!(consumed.state, "state-a");
    assert_eq!(consumed.nonce, "state-a-nonce");
    assert_eq!(consumed.pkce_verifier, "state-a-verifier");
    assert_eq!(consumed.expires_at, UnixMillis::new(2_000));
    assert!(
        store
            .consume("state-a".into(), now)
            .await
            .unwrap_or_else(|_| panic!("consume must succeed"))
            .is_none(),
        "an attempt must be consumable only once"
    );

    let store = new_store().await;
    assert!(
        store
            .consume("unknown".into(), now)
            .await
            .unwrap_or_else(|_| panic!("consume must succeed"))
            .is_none(),
        "an unknown state must not match"
    );

    let store = new_store().await;
    store
        .issue(attempt("state-b", 1_000), now)
        .await
        .unwrap_or_else(|_| panic!("issue must succeed"));
    assert!(
        store
            .consume("state-b".into(), now)
            .await
            .unwrap_or_else(|_| panic!("consume must succeed"))
            .is_none(),
        "an attempt whose expires_at <= now must be expired"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// メモリー実装自身が契約を満たすことを確かめる。
    #[tokio::test]
    async fn in_memory_store_satisfies_the_contract() {
        check_login_attempt_store_contract(|| async { InMemoryLoginAttemptStore::default() }).await;
    }
}
