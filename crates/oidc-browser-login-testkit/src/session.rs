//! feature `session`の試験用部品。メモリーstoreと[`WebSessionStore`]契約試験。

use std::{collections::HashMap, sync::Mutex, time::Duration};

use oidc_browser_login::{
    UnixMillis,
    session::{AuthenticatedWebSession, Principal, TokenDigest, WebSessionRecord, WebSessionStore},
};

use crate::Never;

struct StoredSession {
    csrf_digest: [u8; 32],
    principal: Principal,
    idle_expires_at_ms: i64,
    absolute_expires_at_ms: i64,
}

/// [`WebSessionStore`]契約のメモリー実装。契約試験の参照実装でもある。
#[derive(Default)]
pub struct InMemoryWebSessionStore {
    sessions: Mutex<HashMap<[u8; 32], StoredSession>>,
}

impl WebSessionStore for InMemoryWebSessionStore {
    type Error = Never;

    async fn issue(&self, record: WebSessionRecord, _now: UnixMillis) -> Result<(), Self::Error> {
        self.sessions.lock().expect("session store lock").insert(
            *record.session_digest.as_bytes(),
            StoredSession {
                csrf_digest: *record.csrf_digest.as_bytes(),
                principal: record.principal,
                idle_expires_at_ms: record.idle_expires_at.get(),
                absolute_expires_at_ms: record.absolute_expires_at.get(),
            },
        );
        Ok(())
    }

    async fn lookup_and_extend(
        &self,
        session_digest: TokenDigest,
        now: UnixMillis,
        idle_window: Duration,
    ) -> Result<Option<AuthenticatedWebSession>, Self::Error> {
        let mut sessions = self.sessions.lock().expect("session store lock");
        let Some(stored) = sessions.get_mut(session_digest.as_bytes()) else {
            return Ok(None);
        };
        if stored.idle_expires_at_ms <= now.get() || stored.absolute_expires_at_ms <= now.get() {
            return Ok(None);
        }
        let window = i64::try_from(idle_window.as_millis()).unwrap_or(i64::MAX);
        stored.idle_expires_at_ms = stored
            .absolute_expires_at_ms
            .min(now.get().saturating_add(window));
        Ok(Some(AuthenticatedWebSession {
            principal: stored.principal.clone(),
            idle_expires_at: UnixMillis::new(stored.idle_expires_at_ms),
            absolute_expires_at: UnixMillis::new(stored.absolute_expires_at_ms),
        }))
    }

    async fn csrf_digest(
        &self,
        session_digest: TokenDigest,
    ) -> Result<Option<TokenDigest>, Self::Error> {
        Ok(self
            .sessions
            .lock()
            .expect("session store lock")
            .get(session_digest.as_bytes())
            .map(|stored| TokenDigest::from_bytes(stored.csrf_digest)))
    }

    async fn revoke(
        &self,
        session_digest: TokenDigest,
        _now: UnixMillis,
    ) -> Result<(), Self::Error> {
        self.sessions
            .lock()
            .expect("session store lock")
            .remove(session_digest.as_bytes());
        Ok(())
    }
}

/// [`WebSessionStore`]実装が満たすべき契約を確かめる。
///
/// `new_store`は呼出しごとに空のstoreを返すこと。確かめる契約は次のとおり。
///
/// - 保存したsessionは、期限内の`lookup_and_extend`が
///   `idle_expires_at = min(absolute_expires_at, now + idle_window)`へ延長して返す
/// - `idle_expires_at <= now`または`absolute_expires_at <= now`は`None`
/// - 未知のdigestは`lookup_and_extend`・`csrf_digest`とも`None`、`revoke`は成功する
/// - `csrf_digest`は保存済みdigestを返すだけで比較をしない
/// - `revoke`後は`lookup_and_extend`も`csrf_digest`も`None`
pub async fn check_web_session_store_contract<S, F, Fut>(new_store: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
    S: WebSessionStore,
{
    let principal =
        Principal::new("https://id.example.test".into(), "user-1".into()).expect("principal");
    let record = |session: &str, csrf: &str, idle: i64, absolute: i64| WebSessionRecord {
        session_digest: TokenDigest::of(session),
        csrf_digest: TokenDigest::of(csrf),
        principal: principal.clone(),
        idle_expires_at: UnixMillis::new(idle),
        absolute_expires_at: UnixMillis::new(absolute),
    };
    let lookup_must_succeed = "lookup_and_extend must succeed";
    let csrf_must_succeed = "csrf_digest must succeed";

    // 期限内の検索はidle期限を絶対期限を上限として延長する。
    let store = new_store().await;
    store
        .issue(
            record("session-a", "csrf-a", 2_000, 5_000),
            UnixMillis::new(1_000),
        )
        .await
        .unwrap_or_else(|_| panic!("issue must succeed"));
    let session = store
        .lookup_and_extend(
            TokenDigest::of("session-a"),
            UnixMillis::new(1_500),
            Duration::from_millis(10_000),
        )
        .await
        .unwrap_or_else(|_| panic!("{lookup_must_succeed}"))
        .expect("a stored session must be returned while valid");
    assert_eq!(session.principal, principal);
    assert_eq!(
        session.idle_expires_at,
        UnixMillis::new(5_000),
        "extension must be capped by the absolute expiry"
    );
    assert_eq!(session.absolute_expires_at, UnixMillis::new(5_000));
    let session = store
        .lookup_and_extend(
            TokenDigest::of("session-a"),
            UnixMillis::new(1_500),
            Duration::from_millis(1_000),
        )
        .await
        .unwrap_or_else(|_| panic!("{lookup_must_succeed}"))
        .expect("a stored session must be returned while valid");
    assert_eq!(
        session.idle_expires_at,
        UnixMillis::new(2_500),
        "extension must follow now + idle_window when below the absolute expiry"
    );

    // CSRF digestは保存した値を比較せずに返す。
    let stored_csrf = store
        .csrf_digest(TokenDigest::of("session-a"))
        .await
        .unwrap_or_else(|_| panic!("{csrf_must_succeed}"))
        .expect("a stored csrf digest must be returned");
    assert!(stored_csrf.constant_time_eq(&TokenDigest::of("csrf-a")));
    assert!(!stored_csrf.constant_time_eq(&TokenDigest::of("csrf-b")));

    // 失効後はどちらも見えない。
    store
        .revoke(TokenDigest::of("session-a"), UnixMillis::new(1_600))
        .await
        .unwrap_or_else(|_| panic!("revoke must succeed"));
    assert!(
        store
            .lookup_and_extend(
                TokenDigest::of("session-a"),
                UnixMillis::new(1_600),
                Duration::from_millis(1_000),
            )
            .await
            .unwrap_or_else(|_| panic!("{lookup_must_succeed}"))
            .is_none(),
        "a revoked session must not authenticate"
    );
    assert!(
        store
            .csrf_digest(TokenDigest::of("session-a"))
            .await
            .unwrap_or_else(|_| panic!("{csrf_must_succeed}"))
            .is_none(),
        "a revoked session must not expose its csrf digest"
    );

    // 未知のdigestはNoneで、revokeは成功する。
    let store = new_store().await;
    assert!(
        store
            .lookup_and_extend(
                TokenDigest::of("unknown"),
                UnixMillis::new(1_000),
                Duration::from_millis(1_000),
            )
            .await
            .unwrap_or_else(|_| panic!("{lookup_must_succeed}"))
            .is_none()
    );
    assert!(
        store
            .csrf_digest(TokenDigest::of("unknown"))
            .await
            .unwrap_or_else(|_| panic!("{csrf_must_succeed}"))
            .is_none()
    );
    store
        .revoke(TokenDigest::of("unknown"), UnixMillis::new(1_000))
        .await
        .unwrap_or_else(|_| panic!("revoking an unknown session must succeed"));

    // idle期限と絶対期限は、いずれもnow以下で期限切れになる(境界を含む)。
    let store = new_store().await;
    store
        .issue(
            record("session-b", "csrf-b", 1_000, 5_000),
            UnixMillis::new(500),
        )
        .await
        .unwrap_or_else(|_| panic!("issue must succeed"));
    assert!(
        store
            .lookup_and_extend(
                TokenDigest::of("session-b"),
                UnixMillis::new(1_000),
                Duration::from_millis(1_000),
            )
            .await
            .unwrap_or_else(|_| panic!("{lookup_must_succeed}"))
            .is_none(),
        "a session whose idle expiry <= now must be expired"
    );
    // 絶対期限は延長の上限であり、到達後は期限切れになる(境界を含む)。
    // adapterのschemaは idle <= absolute を前提にできるため、それを満たす値だけを使う。
    let store = new_store().await;
    store
        .issue(
            record("session-c", "csrf-c", 1_500, 2_000),
            UnixMillis::new(500),
        )
        .await
        .unwrap_or_else(|_| panic!("issue must succeed"));
    let session = store
        .lookup_and_extend(
            TokenDigest::of("session-c"),
            UnixMillis::new(1_400),
            Duration::from_millis(10_000),
        )
        .await
        .unwrap_or_else(|_| panic!("{lookup_must_succeed}"))
        .expect("a stored session must be returned while valid");
    assert_eq!(session.idle_expires_at, UnixMillis::new(2_000));
    assert!(
        store
            .lookup_and_extend(
                TokenDigest::of("session-c"),
                UnixMillis::new(2_000),
                Duration::from_millis(1_000),
            )
            .await
            .unwrap_or_else(|_| panic!("{lookup_must_succeed}"))
            .is_none(),
        "a session whose absolute expiry <= now must be expired"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FixedClock, SequenceEntropy};
    use oidc_browser_login::session::{SessionLifetime, WebSessions};

    /// メモリー実装自身が契約を満たすことを確かめる。
    #[tokio::test]
    async fn in_memory_store_satisfies_the_contract() {
        check_web_session_store_contract(|| async { InMemoryWebSessionStore::default() }).await;
    }

    /// use-case全体(発行→検証→CSRF→失効)がメモリーstoreで動くことを確かめる。
    #[tokio::test]
    async fn web_sessions_issue_authenticate_and_revoke() {
        let sessions = WebSessions::new(
            InMemoryWebSessionStore::default(),
            FixedClock(UnixMillis::new(1_000)),
            SequenceEntropy::new(["session", "csrf"]),
            SessionLifetime::default(),
        );
        let principal =
            Principal::new("https://id.example.test".into(), "user-1".into()).expect("principal");
        let issued = sessions.issue(principal.clone()).await.expect("issue");
        assert_eq!(issued.principal, principal);
        assert_eq!(issued.idle_expires_at, UnixMillis::new(1_000 + 86_400_000));
        assert_eq!(
            issued.absolute_expires_at,
            UnixMillis::new(1_000 + 604_800_000)
        );

        let authenticated = sessions
            .authenticate(&issued.session_token)
            .await
            .expect("authenticate")
            .expect("session is valid");
        assert_eq!(authenticated.principal, principal);
        assert!(
            sessions
                .verify_csrf(&issued.session_token, &issued.csrf_token)
                .await
                .expect("verify csrf")
        );
        assert!(
            !sessions
                .verify_csrf(&issued.session_token, "forged-csrf")
                .await
                .expect("verify csrf")
        );

        sessions
            .revoke(&issued.session_token)
            .await
            .expect("revoke");
        assert!(
            sessions
                .authenticate(&issued.session_token)
                .await
                .expect("authenticate")
                .is_none()
        );
    }
}
