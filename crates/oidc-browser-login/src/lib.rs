//! ブラウザーからのOIDCログイン(Authorization Code + PKCE)を検証する製品非依存crate。
//!
//! 対象は「自前でホストするWebアプリケーションが、標準OIDC IdPで利用者を認証する」構成です。
//! このcrateはOIDC providerとの通信とID tokenの検証だけを担い、HTTP framework、データベース、
//! 特定のIdP製品へは依存しません。ログイン試行の保存は[`LoginAttemptStore`]、時刻は[`Clock`]、
//! 乱数は[`Entropy`]の各portを通じて呼出し側が供給します。
//!
//! 検証済みの結果は[`VerifiedIdentity`]と[`VerifiedGroups`]でのみ表現し、これらはcrateの外から
//! 構築できません。「署名・issuer・audience・nonceの検証に成功した後でだけclaimを読める」という
//! 順序を型で保証するためです。
//!
//! 認可(誰の利用を許可するか)はこのcrateの責務外です。呼出し側が
//! [`VerifiedIdentity`]のclaim値を自身の設定と突き合わせて判定してください。

#[cfg(feature = "cookie")]
pub mod cookie;
#[cfg(feature = "session")]
pub mod session;

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub use openidconnect::core::CoreJwsSigningAlgorithm as OidcSigningAlgorithm;
pub use openidconnect::reqwest;
use openidconnect::{
    AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use serde::Deserialize;
use url::{Host, Url};

/// ID token全体として受理する最大バイト数。fail closedの上限であり設定で変更できない。
pub const MAX_ID_TOKEN_BYTES: usize = 16 * 1024;
/// 1つのID tokenから受理するclaim値(group名など)の最大件数。設定で変更できない。
pub const MAX_GROUPS_PER_ID_TOKEN: usize = 128;
/// claim値1件として受理する最大バイト数。設定で変更できない。
pub const MAX_GROUP_NAME_BYTES: usize = 256;

/// ログイン試行の既定の有効期間。
pub const DEFAULT_ATTEMPT_TTL: Duration = Duration::from_secs(10 * 60);

/// 構造化ログへ記録するevent名。利用側の監査基盤がこの名前で購読できる。
pub mod audit {
    /// 遅延discoveryが成功した。
    pub const DISCOVERY_COMPLETED: &str = "oidc.discovery.completed";
    /// 遅延discoveryが失敗した。
    pub const DISCOVERY_FAILED: &str = "oidc.discovery.failed";
}

/// UNIX epochからの経過ミリ秒。呼出し側の時刻表現との写像はadapterで行う。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixMillis(i64);

impl UnixMillis {
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

/// 現在時刻の供給port。試験実装は固定時刻を返せる。
pub trait Clock: Send + Sync {
    fn now(&self) -> UnixMillis;
}

/// 乱数の供給port。実装は暗号学的に安全な乱数を使う。試験実装は決定的な値を供給できる。
pub trait Entropy: Send + Sync {
    /// 推測不能で一意な不透明tokenを返す。state、nonce、PKCE verifierに使う。
    fn opaque_token(&self) -> String;
}

/// OIDC認可requestに一度だけ対応するstate、nonce、PKCE verifier。
///
/// stateは呼出し側のstoreでhash保存するなど、平文の保存期間を短くすることを推奨する。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginAttempt {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub expires_at: UnixMillis,
}

/// ログイン試行の保存port。
///
/// 契約: `issue`で保存した試行は、同じ`state`での最初の`consume`だけが返す(一度きり)。
/// `expires_at <= now`の試行は期限切れとして返さない。未知の`state`は`None`を返す。
/// この契約はtestkitの契約試験で確認できる。
pub trait LoginAttemptStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn issue(
        &self,
        attempt: LoginAttempt,
        now: UnixMillis,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn consume(
        &self,
        state: String,
        now: UnixMillis,
    ) -> impl Future<Output = Result<Option<LoginAttempt>, Self::Error>> + Send;
}

/// token endpointへのclient認証方式。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TokenEndpointAuth {
    /// 既定。credentialをPOST本文で送る(`client_secret_post`)。
    #[default]
    ClientSecretPost,
    /// credentialをAuthorizationヘッダーで送る(`client_secret_basic`)。
    ClientSecretBasic,
}

/// OIDC providerへの接続設定。[`OidcSettings::new`]の既定値から`with_*`で調整する。
#[derive(Clone)]
pub struct OidcSettings {
    issuer_url: IssuerUrl,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
    cookie_path: String,
    scopes: Vec<String>,
    group_claim: String,
    allowed_algorithms: Vec<OidcSigningAlgorithm>,
    token_endpoint_auth: TokenEndpointAuth,
    attempt_ttl: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SettingsError {
    #[error("OIDC issuer URL is invalid")]
    InvalidIssuerUrl,
    #[error("base URL must be an absolute HTTPS URL")]
    InvalidBaseUrl,
    #[error("OIDC client credentials must not be empty")]
    EmptyCredential,
    #[error("OIDC group claim name must not be empty")]
    EmptyGroupClaim,
    #[error("at least one ID token signing algorithm must be allowed")]
    NoAllowedAlgorithm,
}

impl OidcSettings {
    /// 既定値で設定を作る。
    ///
    /// 既定は、追加scopeが`profile`/`email`/`groups_name`、claim名が`groups`、
    /// 署名アルゴリズムがES256のみ、client認証が`client_secret_post`。IdPに合わせて
    /// `with_*`で調整する。`base_url`はアプリケーション自身の公開URLで、callback URLと
    /// cookie pathの導出に使う。
    pub fn new(
        issuer_url: String,
        client_id: String,
        client_secret: String,
        base_url: &str,
    ) -> Result<Self, SettingsError> {
        let issuer_url = validate_issuer_url(issuer_url)?;
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            return Err(SettingsError::EmptyCredential);
        }
        let redirect_url = callback_url(base_url)?;
        let cookie_path = cookie_path(base_url)?;
        Ok(Self {
            issuer_url,
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            redirect_url,
            cookie_path,
            scopes: vec!["profile".into(), "email".into(), "groups_name".into()],
            group_claim: "groups".into(),
            allowed_algorithms: vec![OidcSigningAlgorithm::EcdsaP256Sha256],
            token_endpoint_auth: TokenEndpointAuth::default(),
            attempt_ttl: DEFAULT_ATTEMPT_TTL,
        })
    }

    /// `openid`以外に要求する追加scope。`openid`はライブラリが常に付与する。
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// 所属情報を読むclaim名。既定は`groups`。
    pub fn with_group_claim(mut self, claim: String) -> Result<Self, SettingsError> {
        if claim.trim().is_empty() {
            return Err(SettingsError::EmptyGroupClaim);
        }
        self.group_claim = claim;
        Ok(self)
    }

    /// 許可するID token署名アルゴリズム。既定はES256のみ。
    ///
    /// RS256を許可する構成のセキュリティー上の考慮はSECURITY.mdを参照。
    pub fn with_allowed_algorithms(
        mut self,
        algorithms: Vec<OidcSigningAlgorithm>,
    ) -> Result<Self, SettingsError> {
        if algorithms.is_empty() {
            return Err(SettingsError::NoAllowedAlgorithm);
        }
        self.allowed_algorithms = algorithms;
        Ok(self)
    }

    pub fn with_token_endpoint_auth(mut self, auth: TokenEndpointAuth) -> Self {
        self.token_endpoint_auth = auth;
        self
    }

    /// ログイン試行(state、nonce、PKCE verifier)の有効期間。既定は10分。
    pub fn with_attempt_ttl(mut self, ttl: Duration) -> Self {
        self.attempt_ttl = ttl;
        self
    }

    pub fn issuer_url(&self) -> &IssuerUrl {
        &self.issuer_url
    }
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }
    pub fn client_secret(&self) -> &ClientSecret {
        &self.client_secret
    }
    pub fn redirect_url(&self) -> &RedirectUrl {
        &self.redirect_url
    }
    /// ログイン関連cookieのPath属性に使える、base URLから導出したpath。
    pub fn cookie_path(&self) -> &str {
        &self.cookie_path
    }
    pub fn group_claim(&self) -> &str {
        &self.group_claim
    }
}

/// issuer URLの受理条件。原則HTTPSのみで、userinfo・query・fragmentを持たない絶対URLに限る。
///
/// 例外として、hostがloopback(`127.0.0.1`、`::1`、`localhost`)の場合だけHTTPを受理する。
/// testkitの疑似IdPなど、同一ホスト内の試験のためであり、実配備はHTTPSを使うこと。
fn validate_issuer_url(value: String) -> Result<IssuerUrl, SettingsError> {
    let url = Url::parse(&value).map_err(|_| SettingsError::InvalidIssuerUrl)?;
    let loopback = matches!(
        url.host(),
        Some(Host::Ipv4(ip)) if ip.is_loopback()
    ) || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(Host::Domain(domain)) if domain == "localhost");
    let scheme_allowed = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !scheme_allowed
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SettingsError::InvalidIssuerUrl);
    }
    IssuerUrl::new(value).map_err(|_| SettingsError::InvalidIssuerUrl)
}

fn callback_url(base_url: &str) -> Result<RedirectUrl, SettingsError> {
    let mut url = Url::parse(base_url).map_err(|_| SettingsError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SettingsError::InvalidBaseUrl);
    }
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/auth/oidc/callback"));
    RedirectUrl::new(url.into()).map_err(|_| SettingsError::InvalidBaseUrl)
}

fn cookie_path(base_url: &str) -> Result<String, SettingsError> {
    let url = Url::parse(base_url).map_err(|_| SettingsError::InvalidBaseUrl)?;
    let path = url.path().trim_end_matches('/');
    Ok(if path.is_empty() {
        "/".into()
    } else {
        path.into()
    })
}

fn allowed_id_token_algorithms(
    allowed: &[OidcSigningAlgorithm],
    supported: &[OidcSigningAlgorithm],
) -> Vec<OidcSigningAlgorithm> {
    allowed
        .iter()
        .filter(|algorithm| supported.contains(algorithm))
        .cloned()
        .collect()
}

/// Discovery済みの外部OIDCクライアント。
pub type DiscoveredOidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiscoveryError {
    #[error("OIDC HTTP client could not be initialized")]
    HttpClient,
    #[error("OIDC discovery failed")]
    Discovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BeginLoginError {
    #[error("OIDC provider is not reachable")]
    Discovery,
    #[error("login attempt could not be stored")]
    Store,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CallbackError {
    #[error("OIDC callback was rejected")]
    Rejected(CallbackRejection),
    #[error("OIDC callback could not be processed")]
    Unavailable,
}

/// OAuth callbackの安全に記録できる失敗段階。token、code、stateなどの値は含めない。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackRejection {
    State,
    CodeExchange,
    MissingIdToken,
    Claims,
    Identity,
    Groups,
}

impl CallbackError {
    /// 診断ログへ記録できる失敗段階の識別子。secretや利用者情報を含まない。
    pub const fn diagnostic_stage(self) -> &'static str {
        match self {
            Self::Rejected(CallbackRejection::State) => "state",
            Self::Rejected(CallbackRejection::CodeExchange) => "code-exchange",
            Self::Rejected(CallbackRejection::MissingIdToken) => "missing-id-token",
            Self::Rejected(CallbackRejection::Claims) => "id-token-claims",
            Self::Rejected(CallbackRejection::Identity) => "identity",
            Self::Rejected(CallbackRejection::Groups) => "groups",
            Self::Unavailable => "storage",
        }
    }
}

/// 署名・issuer・audience・nonceを検証済みのID tokenから読んだ所属claimの値。
///
/// crateの外からは構築できない。検証に成功した経路でだけ値が存在することを型で表す。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGroups {
    groups: BTreeSet<String>,
}

impl VerifiedGroups {
    pub fn contains(&self, value: &str) -> bool {
        self.groups.contains(value)
    }

    pub fn into_names(self) -> Vec<String> {
        self.groups.into_iter().collect()
    }
}

/// ログインcallbackの検証成功時にだけ返す、署名検証済みのOIDC identity。
///
/// `issuer`と`subject`の組が利用者の同一性を表す。認可の判定は呼出し側が
/// `groups`と自身の設定を突き合わせて行う。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedIdentity {
    pub issuer: String,
    pub subject: String,
    pub groups: VerifiedGroups,
}

#[derive(Deserialize)]
struct GroupClaimPayload {
    #[serde(flatten)]
    claims: serde_json::Map<String, serde_json::Value>,
}

/// 検証済みID tokenのpayloadから、設定したclaim名の値を読む。
///
/// この関数はJWTの署名検証をしない。必ず`IdToken::claims`の成功後にだけ呼び出す。claimの値は
/// 文字列配列に加えて単一の文字列も受理する(IdPにより単数で発行されるため)。claimが欠落、
/// それ以外の型、空の値を含む場合はfail closedで拒否する。claim名が`email`の場合は、
/// 未検証のメールアドレスを認可の根拠にしないため`email_verified`がtrueであることも要求する。
fn groups_from_verified_id_token(
    id_token: &str,
    group_claim: &str,
) -> Result<VerifiedGroups, CallbackRejection> {
    if group_claim.is_empty() || id_token.len() > MAX_ID_TOKEN_BYTES {
        return Err(CallbackRejection::Groups);
    }
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or(CallbackRejection::Groups)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| CallbackRejection::Groups)?;
    let payload = serde_json::from_slice::<GroupClaimPayload>(&payload)
        .map_err(|_| CallbackRejection::Groups)?;
    if group_claim == "email"
        && payload
            .claims
            .get("email_verified")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(CallbackRejection::Groups);
    }
    let claim = payload
        .claims
        .get(group_claim)
        .ok_or(CallbackRejection::Groups)?;
    let single = std::slice::from_ref(claim);
    let values: &[serde_json::Value] = match claim {
        serde_json::Value::Array(values) => values,
        serde_json::Value::String(_) => single,
        _ => return Err(CallbackRejection::Groups),
    };
    if values.len() > MAX_GROUPS_PER_ID_TOKEN {
        return Err(CallbackRejection::Groups);
    }
    let mut groups = BTreeSet::new();
    for value in values {
        let value = value
            .as_str()
            .filter(|value| !value.trim().is_empty() && value.len() <= MAX_GROUP_NAME_BYTES)
            .ok_or(CallbackRejection::Groups)?;
        groups.insert(value.to_owned());
    }
    Ok(VerifiedGroups { groups })
}

/// Discovery済みのOIDCログイン。認可URLの発行とcallbackの検証を行う。
#[derive(Clone)]
pub struct OidcLogin {
    client: DiscoveredOidcClient,
    http_client: reqwest::Client,
    cookie_path: String,
    scopes: Vec<String>,
    group_claim: String,
    attempt_ttl: Duration,
}

impl OidcLogin {
    pub async fn discover(settings: &OidcSettings) -> Result<Self, DiscoveryError> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| DiscoveryError::HttpClient)?;
        Self::discover_with_http_client(settings, http_client).await
    }

    /// Discoveryとtoken exchangeに使うHTTP clientを明示する。内部CAを使う配備では、
    /// 呼出し側が検証済みPEMをroot certificateとして追加したclientを渡す。
    pub async fn discover_with_http_client(
        settings: &OidcSettings,
        http_client: reqwest::Client,
    ) -> Result<Self, DiscoveryError> {
        let metadata =
            CoreProviderMetadata::discover_async(settings.issuer_url().clone(), &http_client)
                .await
                .map_err(|_| DiscoveryError::Discovery)?;
        let signing_algorithms = allowed_id_token_algorithms(
            &settings.allowed_algorithms,
            metadata.id_token_signing_alg_values_supported(),
        );
        if signing_algorithms.is_empty() {
            return Err(DiscoveryError::Discovery);
        }
        let metadata = metadata.set_id_token_signing_alg_values_supported(signing_algorithms);
        Ok(Self {
            client: CoreClient::from_provider_metadata(
                metadata,
                settings.client_id().clone(),
                Some(settings.client_secret().clone()),
            )
            .set_auth_type(match settings.token_endpoint_auth {
                TokenEndpointAuth::ClientSecretPost => AuthType::RequestBody,
                TokenEndpointAuth::ClientSecretBasic => AuthType::BasicAuth,
            })
            .set_redirect_uri(settings.redirect_url().clone()),
            http_client,
            cookie_path: settings.cookie_path().into(),
            scopes: settings.scopes.clone(),
            group_claim: settings.group_claim.clone(),
            attempt_ttl: settings.attempt_ttl,
        })
    }

    /// ログイン関連cookieのPath属性に使える、base URLから導出したpath。
    pub fn cookie_path(&self) -> &str {
        &self.cookie_path
    }

    /// ログイン試行を保存し、IdPの認可endpointへのredirect先URLを返す。
    pub async fn begin_login<Attempts, Random, Time>(
        &self,
        attempts: &Attempts,
        entropy: &Random,
        clock: &Time,
    ) -> Result<String, BeginLoginError>
    where
        Attempts: LoginAttemptStore,
        Random: Entropy,
        Time: Clock,
    {
        let now = clock.now();
        let ttl = i64::try_from(self.attempt_ttl.as_millis()).unwrap_or(i64::MAX);
        let pending = LoginAttempt {
            state: entropy.opaque_token(),
            nonce: entropy.opaque_token(),
            pkce_verifier: entropy.opaque_token(),
            expires_at: UnixMillis::new(now.get().saturating_add(ttl)),
        };
        attempts
            .issue(pending.clone(), now)
            .await
            .map_err(|_| BeginLoginError::Store)?;
        let verifier = PkceCodeVerifier::new(pending.pkce_verifier);
        let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        let state = pending.state;
        let nonce = pending.nonce;
        let (url, _, _) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || CsrfToken::new(state),
                move || Nonce::new(nonce),
            )
            .set_pkce_challenge(challenge)
            // openidはライブラリが常に付与する。追加分は設定から渡す。
            .add_scopes(self.scopes.iter().cloned().map(Scope::new))
            .url();
        Ok(url.into())
    }

    /// callbackの`code`と`state`を検証し、検証済みidentityを返す。
    ///
    /// stateの照合、authorization codeの交換、ID tokenの署名・issuer・audience・nonceの検証、
    /// 所属claimの読み取りを、この順で行う。
    pub async fn complete_login<Attempts, Time>(
        &self,
        attempts: &Attempts,
        clock: &Time,
        code: &str,
        state: &str,
    ) -> Result<VerifiedIdentity, CallbackError>
    where
        Attempts: LoginAttemptStore,
        Time: Clock,
    {
        let pending = attempts
            .consume(state.to_owned(), clock.now())
            .await
            .map_err(|_| CallbackError::Unavailable)?
            .ok_or(CallbackError::Rejected(CallbackRejection::State))?;
        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| CallbackError::Rejected(CallbackRejection::CodeExchange))?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
            .request_async(&self.http_client)
            .await
            .map_err(|_| CallbackError::Rejected(CallbackRejection::CodeExchange))?;
        let id_token = token
            .id_token()
            .ok_or(CallbackError::Rejected(CallbackRejection::MissingIdToken))?;
        let claims = id_token
            .claims(&self.client.id_token_verifier(), &Nonce::new(pending.nonce))
            .map_err(|_| CallbackError::Rejected(CallbackRejection::Claims))?;
        let groups = groups_from_verified_id_token(&id_token.to_string(), &self.group_claim)
            .map_err(CallbackError::Rejected)?;
        Ok(VerifiedIdentity {
            issuer: claims.issuer().as_str().to_owned(),
            subject: claims.subject().as_str().to_owned(),
            groups,
        })
    }
}

/// 初回利用時にdiscoveryを行うOIDCログイン。
///
/// アプリケーション起動時にIdPへ到達できなくても起動を継続でき、最初のログイン要求で
/// discoveryを再試行する。成功した結果は保持して再利用する。
pub struct LazyOidcLogin<Attempts, Time, Random> {
    attempts: Attempts,
    clock: Time,
    entropy: Random,
    settings: OidcSettings,
    http_client: reqwest::Client,
    discovered: Arc<tokio::sync::RwLock<Option<OidcLogin>>>,
}

impl<Attempts, Time, Random> LazyOidcLogin<Attempts, Time, Random> {
    /// `discovered`へ起動時にdiscovery済みの結果を渡すと、それを初期値として使う。
    pub fn new(
        attempts: Attempts,
        clock: Time,
        entropy: Random,
        settings: OidcSettings,
        http_client: reqwest::Client,
        discovered: Option<OidcLogin>,
    ) -> Self {
        Self {
            attempts,
            clock,
            entropy,
            settings,
            http_client,
            discovered: Arc::new(tokio::sync::RwLock::new(discovered)),
        }
    }

    async fn login(&self) -> Result<OidcLogin, DiscoveryError> {
        if let Some(login) = self.discovered.read().await.clone() {
            return Ok(login);
        }
        let login = OidcLogin::discover_with_http_client(&self.settings, self.http_client.clone())
            .await
            .inspect_err(|_| {
                // event名は文字列走査でも見つかるようliteralで書く([`audit`]の定数と一致)。
                tracing::warn!(
                    event = "oidc.discovery.failed",
                    reason = "unavailable",
                    "OIDC discovery retry failed"
                );
            })?;
        tracing::info!(
            event = "oidc.discovery.completed",
            "OIDC discovery succeeded"
        );
        let mut discovered = self.discovered.write().await;
        Ok(discovered.get_or_insert(login).clone())
    }
}

impl<Attempts, Time, Random> LazyOidcLogin<Attempts, Time, Random>
where
    Attempts: LoginAttemptStore,
    Time: Clock,
    Random: Entropy,
{
    pub async fn begin_login(&self) -> Result<String, BeginLoginError> {
        self.login()
            .await
            .map_err(|_| BeginLoginError::Discovery)?
            .begin_login(&self.attempts, &self.entropy, &self.clock)
            .await
    }

    pub async fn complete_login(
        &self,
        code: &str,
        state: &str,
    ) -> Result<VerifiedIdentity, CallbackError> {
        self.login()
            .await
            .map_err(|_| CallbackError::Unavailable)?
            .complete_login(&self.attempts, &self.clock, code, state)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> OidcSettings {
        OidcSettings::new(
            "https://id.example.test".into(),
            "client".into(),
            "secret".into(),
            "https://app.example.test",
        )
        .expect("valid settings")
    }

    /// tracing呼出しのliteralと公開する監査定数が一致することを確かめる。
    #[test]
    fn audit_constants_match_the_emitted_event_names() {
        assert_eq!(audit::DISCOVERY_COMPLETED, "oidc.discovery.completed");
        assert_eq!(audit::DISCOVERY_FAILED, "oidc.discovery.failed");
    }

    #[test]
    fn preserves_base_subpath() {
        let settings = OidcSettings::new(
            "https://id.example.test".into(),
            "client".into(),
            "secret".into(),
            "https://example.test/app/",
        )
        .expect("settings");
        assert_eq!(
            settings.redirect_url().as_str(),
            "https://example.test/app/auth/oidc/callback"
        );
        assert_eq!(settings.cookie_path(), "/app");
    }

    #[test]
    fn issuer_requires_an_absolute_https_url_without_ambiguous_components() {
        for issuer in [
            "http://id.example.test",
            "https://user@id.example.test",
            "https://id.example.test?tenant=one",
            "https://id.example.test#configuration",
            "/relative",
        ] {
            assert!(matches!(
                OidcSettings::new(
                    issuer.into(),
                    "client".into(),
                    "secret".into(),
                    "https://example.test/",
                ),
                Err(SettingsError::InvalidIssuerUrl)
            ));
        }
    }

    /// loopbackのHTTP issuerは、同一ホスト内の試験のためにだけ受理する。
    #[test]
    fn issuer_accepts_http_only_for_loopback_hosts() {
        for issuer in [
            "http://127.0.0.1:8443",
            "http://localhost:8443",
            "http://[::1]:8443",
        ] {
            assert!(
                OidcSettings::new(
                    issuer.into(),
                    "client".into(),
                    "secret".into(),
                    "https://example.test/",
                )
                .is_ok(),
                "{issuer} should be accepted"
            );
        }
        assert!(matches!(
            OidcSettings::new(
                "http://id.example.test".into(),
                "client".into(),
                "secret".into(),
                "https://example.test/",
            ),
            Err(SettingsError::InvalidIssuerUrl)
        ));
    }

    #[test]
    fn parses_a_configured_group_claim_after_token_verification() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"groups":["server-users"]}"#);
        let token = format!("{header}.{payload}.signature");
        let groups = groups_from_verified_id_token(&token, "groups").expect("groups");
        assert!(groups.contains("server-users"));
    }

    #[test]
    fn rejects_missing_or_non_string_group_claims() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"groups":["server-users",3]}"#);
        let token = format!("{header}.{payload}.signature");
        assert_eq!(
            groups_from_verified_id_token(&token, "groups"),
            Err(CallbackRejection::Groups)
        );
    }

    /// 上限超過はfail closedで拒否する。
    #[test]
    fn rejects_oversized_tokens_groups_and_names() {
        let token = |payload: &str| format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload));

        let oversized_token = format!("h.{}.s", "a".repeat(MAX_ID_TOKEN_BYTES));
        assert_eq!(
            groups_from_verified_id_token(&oversized_token, "groups"),
            Err(CallbackRejection::Groups)
        );

        let many_groups: Vec<String> = (0..=MAX_GROUPS_PER_ID_TOKEN)
            .map(|index| format!("\"group-{index}\""))
            .collect();
        let too_many = token(&format!(r#"{{"groups":[{}]}}"#, many_groups.join(",")));
        assert_eq!(
            groups_from_verified_id_token(&too_many, "groups"),
            Err(CallbackRejection::Groups)
        );

        let long_name = "g".repeat(MAX_GROUP_NAME_BYTES + 1);
        let too_long = token(&format!(r#"{{"groups":["{long_name}"]}}"#));
        assert_eq!(
            groups_from_verified_id_token(&too_long, "groups"),
            Err(CallbackRejection::Groups)
        );
    }

    /// 既定の許可一覧(ES256のみ)は、providerがRS256しか出さない場合に空へ縮退する。
    #[test]
    fn id_token_algorithms_are_limited_to_the_allowed_list() {
        let default_allowed = [OidcSigningAlgorithm::EcdsaP256Sha256];
        assert_eq!(
            allowed_id_token_algorithms(
                &default_allowed,
                &[
                    OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                    OidcSigningAlgorithm::EcdsaP256Sha256,
                    OidcSigningAlgorithm::HmacSha256,
                ]
            ),
            vec![OidcSigningAlgorithm::EcdsaP256Sha256]
        );
        assert!(
            allowed_id_token_algorithms(
                &default_allowed,
                &[OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256]
            )
            .is_empty()
        );
        // RS256を許可した場合だけ交差に現れる。
        assert_eq!(
            allowed_id_token_algorithms(
                &[
                    OidcSigningAlgorithm::EcdsaP256Sha256,
                    OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                ],
                &[OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256]
            ),
            vec![OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256]
        );
    }

    /// claimの単一文字列は1件の集合として受理し、emailで認可する場合はemail_verifiedを要求する。
    #[test]
    fn email_claims_require_verification_and_accept_single_strings() {
        let token = |payload: &str| format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload));

        let verified = token(r#"{"email":"a@example.com","email_verified":true}"#);
        let groups = groups_from_verified_id_token(&verified, "email").expect("verified email");
        assert!(groups.contains("a@example.com"));

        let unverified = token(r#"{"email":"a@example.com","email_verified":false}"#);
        assert_eq!(
            groups_from_verified_id_token(&unverified, "email"),
            Err(CallbackRejection::Groups)
        );
        let missing_flag = token(r#"{"email":"a@example.com"}"#);
        assert_eq!(
            groups_from_verified_id_token(&missing_flag, "email"),
            Err(CallbackRejection::Groups)
        );

        // email以外のclaimでも単一文字列を受理する。email_verifiedは要求しない。
        let single = token(r#"{"role":"admin"}"#);
        let groups = groups_from_verified_id_token(&single, "role").expect("single string claim");
        assert!(groups.contains("admin"));
    }

    /// 空のclient credentialとclaim名、空のアルゴリズム一覧は設定段階で拒否する。
    #[test]
    fn settings_reject_empty_values() {
        assert_eq!(
            OidcSettings::new(
                "https://id.example.test".into(),
                "".into(),
                "secret".into(),
                "https://app.example.test",
            )
            .err(),
            Some(SettingsError::EmptyCredential)
        );
        assert_eq!(
            settings().with_group_claim(" ".into()).err(),
            Some(SettingsError::EmptyGroupClaim)
        );
        assert_eq!(
            settings().with_allowed_algorithms(Vec::new()).err(),
            Some(SettingsError::NoAllowedAlgorithm)
        );
    }
}
