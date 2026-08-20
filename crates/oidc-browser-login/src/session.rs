//! ログイン後のWeb session管理(feature `session`)。
//!
//! 発行・検証(スライド延長)・CSRF照合・失効のuse-caseと、保存portを提供します。
//! 設計の柱は「storeへ秘密の比較を持ち込ませない」ことです。
//!
//! - storeが受け取るkeyは常にtoken本体ではなく[`TokenDigest`](SHA-256)。storeは
//!   digestの完全一致でindex検索するだけで、秘密同士の比較を行いません。
//! - CSRF照合は、storeが保存済みdigestを返し、比較は[`TokenDigest::constant_time_eq`]
//!   (crate内の定数時間比較)でだけ行います。SQLの`WHERE csrf = ?`のような比較を
//!   port形状として作れなくすることで、非定数時間比較の再発を防ぎます。
//!
//! sessionの発行は検証済みの[`VerifiedIdentity`]から得た[`Principal`]を起点にします。
//! Cookieの発行・解析、Origin検査などのHTTP境界は呼出し側の責務です。

use std::time::Duration;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{Clock, Entropy, UnixMillis, VerifiedIdentity};

/// sessionの未使用(idle)期限の既定値。
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// sessionの絶対期限の既定値。
pub const DEFAULT_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// 認証済み利用者の同一性。`(issuer, subject)`の組で表す。
///
/// 発行の主経路は検証済み[`VerifiedIdentity`]からの変換で、「ID token検証に成功した
/// 場合にだけsessionを発行できる」順序を型で表す。保存済みsessionの復元には
/// 検証付きの[`Principal::new`]を使う。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    issuer: String,
    subject: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("principal issuer and subject must not be empty")]
pub struct InvalidPrincipal;

impl Principal {
    /// 保存済みの値から復元する。空のissuerまたはsubjectは拒否する。
    pub fn new(issuer: String, subject: String) -> Result<Self, InvalidPrincipal> {
        if issuer.trim().is_empty() || subject.trim().is_empty() {
            return Err(InvalidPrincipal);
        }
        Ok(Self { issuer, subject })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }
}

impl From<&VerifiedIdentity> for Principal {
    fn from(identity: &VerifiedIdentity) -> Self {
        Self {
            issuer: identity.issuer.clone(),
            subject: identity.subject.clone(),
        }
    }
}

/// tokenのSHA-256 digest。storeへ渡すkeyは常にこの型で、平文tokenはstoreへ届かない。
///
/// 比較には[`TokenDigest::constant_time_eq`]だけを使う。誤って可変時間の比較を
/// 書けないよう、`PartialEq`は実装しない。
#[derive(Clone, Copy, Debug)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// tokenのdigestを計算する。
    pub fn of(token: &str) -> Self {
        Self(Sha256::digest(token.as_bytes()).into())
    }

    /// 保存済みのdigest値から復元する。
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 定数時間比較。CSRF tokenなど秘密由来の値の照合はこの関数でだけ行う。
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// sessionの未使用期限と絶対期限。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLifetime {
    /// 操作がない場合の期限。操作のたびに絶対期限を上限として延長する。
    pub idle: Duration,
    /// 発行からの上限。延長しない。
    pub absolute: Duration,
}

impl Default for SessionLifetime {
    fn default() -> Self {
        Self {
            idle: DEFAULT_IDLE_TIMEOUT,
            absolute: DEFAULT_ABSOLUTE_TIMEOUT,
        }
    }
}

/// storeへ保存する新規session。平文tokenを含まない。
#[derive(Clone, Debug)]
pub struct WebSessionRecord {
    pub session_digest: TokenDigest,
    pub csrf_digest: TokenDigest,
    pub principal: Principal,
    pub idle_expires_at: UnixMillis,
    pub absolute_expires_at: UnixMillis,
}

/// 期限内と確認できたsession。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedWebSession {
    pub principal: Principal,
    pub idle_expires_at: UnixMillis,
    pub absolute_expires_at: UnixMillis,
}

/// Web sessionの保存port。
///
/// 契約(testkitの契約試験で確認できる):
///
/// - `issue`で保存したsessionは、期限内の`lookup_and_extend`が
///   `idle_expires_at = min(absolute_expires_at, now + idle_window)`へ延長して返す
/// - `idle_expires_at <= now`または`absolute_expires_at <= now`は期限切れとして`None`
/// - 未知のdigestは`None`
/// - `revoke`後は`lookup_and_extend`も`csrf_digest`も`None`
/// - `csrf_digest`は保存済みのCSRF digestを返すだけで、比較をしない
pub trait WebSessionStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn issue(
        &self,
        record: WebSessionRecord,
        now: UnixMillis,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn lookup_and_extend(
        &self,
        session_digest: TokenDigest,
        now: UnixMillis,
        idle_window: Duration,
    ) -> impl Future<Output = Result<Option<AuthenticatedWebSession>, Self::Error>> + Send;

    /// 保存済みCSRF digestを返す。期限は検査しない(呼出し側が`authenticate`の成功後に使う)。
    fn csrf_digest(
        &self,
        session_digest: TokenDigest,
    ) -> impl Future<Output = Result<Option<TokenDigest>, Self::Error>> + Send;

    fn revoke(
        &self,
        session_digest: TokenDigest,
        now: UnixMillis,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// 発行直後にだけ得られる、平文tokenを含むsession。Cookieの発行に使い、保存しない。
#[derive(Clone, Debug)]
pub struct IssuedWebSession {
    pub session_token: String,
    pub csrf_token: String,
    pub principal: Principal,
    pub idle_expires_at: UnixMillis,
    pub absolute_expires_at: UnixMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SessionError {
    #[error("session storage is unavailable")]
    Unavailable,
}

fn saturating_add(now: UnixMillis, duration: Duration) -> UnixMillis {
    let millis = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
    UnixMillis::new(now.get().saturating_add(millis))
}

/// Web sessionのuse-case。発行・検証・CSRF照合・失効を提供する。
pub struct WebSessions<Store, Time, Random> {
    store: Store,
    clock: Time,
    entropy: Random,
    lifetime: SessionLifetime,
}

impl<Store, Time, Random> WebSessions<Store, Time, Random>
where
    Store: WebSessionStore,
    Time: Clock,
    Random: Entropy,
{
    pub fn new(store: Store, clock: Time, entropy: Random, lifetime: SessionLifetime) -> Self {
        Self {
            store,
            clock,
            entropy,
            lifetime,
        }
    }

    /// 認証済み利用者へ新しいsessionを発行する。
    pub async fn issue(&self, principal: Principal) -> Result<IssuedWebSession, SessionError> {
        let now = self.clock.now();
        let session_token = self.entropy.opaque_token();
        let csrf_token = self.entropy.opaque_token();
        let idle_expires_at = saturating_add(now, self.lifetime.idle);
        let absolute_expires_at = saturating_add(now, self.lifetime.absolute);
        self.store
            .issue(
                WebSessionRecord {
                    session_digest: TokenDigest::of(&session_token),
                    csrf_digest: TokenDigest::of(&csrf_token),
                    principal: principal.clone(),
                    idle_expires_at,
                    absolute_expires_at,
                },
                now,
            )
            .await
            .map_err(|_| SessionError::Unavailable)?;
        Ok(IssuedWebSession {
            session_token,
            csrf_token,
            principal,
            idle_expires_at,
            absolute_expires_at,
        })
    }

    /// session tokenを検証し、有効なら未使用期限を延長して返す。
    pub async fn authenticate(
        &self,
        session_token: &str,
    ) -> Result<Option<AuthenticatedWebSession>, SessionError> {
        self.store
            .lookup_and_extend(
                TokenDigest::of(session_token),
                self.clock.now(),
                self.lifetime.idle,
            )
            .await
            .map_err(|_| SessionError::Unavailable)
    }

    /// 提示されたCSRF tokenがsessionに結び付いたものかを、定数時間比較で検証する。
    pub async fn verify_csrf(
        &self,
        session_token: &str,
        csrf_token: &str,
    ) -> Result<bool, SessionError> {
        let stored = self
            .store
            .csrf_digest(TokenDigest::of(session_token))
            .await
            .map_err(|_| SessionError::Unavailable)?;
        Ok(stored.is_some_and(|stored| stored.constant_time_eq(&TokenDigest::of(csrf_token))))
    }

    /// sessionを失効させる。
    pub async fn revoke(&self, session_token: &str) -> Result<(), SessionError> {
        self.store
            .revoke(TokenDigest::of(session_token), self.clock.now())
            .await
            .map_err(|_| SessionError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_rejects_empty_values() {
        assert_eq!(
            Principal::new(" ".into(), "user".into()).err(),
            Some(InvalidPrincipal)
        );
        assert_eq!(
            Principal::new("https://id.example.test".into(), "".into()).err(),
            Some(InvalidPrincipal)
        );
        let principal =
            Principal::new("https://id.example.test".into(), "user-1".into()).expect("principal");
        assert_eq!(principal.issuer(), "https://id.example.test");
        assert_eq!(principal.subject(), "user-1");
    }

    #[test]
    fn token_digests_compare_in_constant_time_only() {
        let digest = TokenDigest::of("token-a");
        assert!(digest.constant_time_eq(&TokenDigest::of("token-a")));
        assert!(!digest.constant_time_eq(&TokenDigest::of("token-b")));
        assert!(
            TokenDigest::from_bytes(*digest.as_bytes()).constant_time_eq(&digest),
            "digestは保存済みバイト列から復元できる"
        );
    }

    #[test]
    fn lifetimes_default_to_a_day_and_a_week() {
        let lifetime = SessionLifetime::default();
        assert_eq!(lifetime.idle, Duration::from_secs(86_400));
        assert_eq!(lifetime.absolute, Duration::from_secs(604_800));
    }
}
