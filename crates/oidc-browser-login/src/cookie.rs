//! session cookieの名前規則と属性の組み立て(feature `cookie`)。
//!
//! HTTP frameworkへは依存せず、`Set-Cookie`ヘッダー値の文字列だけを組み立てます。
//! cookieの解析、送受信、Origin検査は呼出し側の責務です。
//!
//! 名前規則: cookie pathが`/`のとき`__Host-`プレフィックスを使います。`__Host-`は
//! ブラウザー仕様上「Secure、Domainなし、Path=/」を要求するため、サブパス配備では
//! `__Secure-`プレフィックスへ退避します。この分岐を構築時に固定することで、仕様に
//! 反する組合せを作れなくします。
//!
//! 属性方針: `Secure`と`SameSite=Lax`は常時付与、session cookieは`HttpOnly`、
//! CSRF cookieはJavaScriptがヘッダーへ写すため`HttpOnly`を付けず、`Max-Age`は明示します。

use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CookieError {
    #[error("application name must be lowercase alphanumeric with hyphen or underscore")]
    InvalidApplicationName,
    #[error("cookie path must start with '/' and contain no control characters or ';'")]
    InvalidPath,
    #[error("cookie value contains characters that are not allowed")]
    InvalidValue,
}

/// sessionとCSRFのcookie名・path・属性の組。構築時に名前規則を固定する。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCookies {
    session_name: String,
    csrf_name: String,
    path: String,
}

impl SessionCookies {
    /// アプリケーション名とcookie pathから名前を導出する。
    ///
    /// `application`はcookie名の一部になるため、小文字英数字とハイフン・アンダースコア
    /// だけを受理する。`cookie_path`はbase URLから導出したpath(`/`または`/app`など)。
    pub fn new(application: &str, cookie_path: &str) -> Result<Self, CookieError> {
        if application.is_empty()
            || !application
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            return Err(CookieError::InvalidApplicationName);
        }
        if !cookie_path.starts_with('/')
            || cookie_path
                .chars()
                .any(|c| c.is_ascii_control() || c == ';' || c == ' ')
        {
            return Err(CookieError::InvalidPath);
        }
        let prefix = if cookie_path == "/" {
            "__Host-"
        } else {
            "__Secure-"
        };
        Ok(Self {
            session_name: format!("{prefix}{application}_session"),
            csrf_name: format!("{prefix}{application}_csrf"),
            path: cookie_path.to_owned(),
        })
    }

    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    pub fn csrf_name(&self) -> &str {
        &self.csrf_name
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// ログイン成功時の`Set-Cookie`ヘッダー値2件(session、CSRFの順)を組み立てる。
    ///
    /// `max_age`にはsessionの絶対期限を渡す。ブラウザー側の保持期間を期限と一致させ、
    /// 期限切れcookieの再送を避けるため。
    pub fn issue_headers(
        &self,
        session_token: &str,
        csrf_token: &str,
        max_age: Duration,
    ) -> Result<[String; 2], CookieError> {
        validate_value(session_token)?;
        validate_value(csrf_token)?;
        let path = &self.path;
        let seconds = max_age.as_secs();
        Ok([
            format!(
                "{}={session_token}; Path={path}; Secure; HttpOnly; SameSite=Lax; Max-Age={seconds}",
                self.session_name
            ),
            format!(
                "{}={csrf_token}; Path={path}; Secure; SameSite=Lax; Max-Age={seconds}",
                self.csrf_name
            ),
        ])
    }

    /// ログアウト時にcookieを削除する`Set-Cookie`ヘッダー値2件を組み立てる。
    pub fn clear_headers(&self) -> [String; 2] {
        let path = &self.path;
        [
            format!(
                "{}=; Path={path}; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
                self.session_name
            ),
            format!(
                "{}=; Path={path}; Secure; SameSite=Lax; Max-Age=0",
                self.csrf_name
            ),
        ]
    }
}

/// RFC 6265のcookie-valueとして安全な文字だけを受理する。
/// 不透明token(base64url)はすべて通る。
fn validate_value(value: &str) -> Result<(), CookieError> {
    let valid = value
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | ',' | ';' | '\\'));
    if valid {
        Ok(())
    } else {
        Err(CookieError::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_path_uses_the_host_prefix() {
        let cookies = SessionCookies::new("renkan", "/").expect("cookies");
        assert_eq!(cookies.session_name(), "__Host-renkan_session");
        assert_eq!(cookies.csrf_name(), "__Host-renkan_csrf");
    }

    /// `__Host-`はPath=/を要求するため、サブパスでは`__Secure-`へ退避する。
    #[test]
    fn subpaths_fall_back_to_the_secure_prefix() {
        let cookies = SessionCookies::new("marginalis", "/app").expect("cookies");
        assert_eq!(cookies.session_name(), "__Secure-marginalis_session");
        assert_eq!(cookies.csrf_name(), "__Secure-marginalis_csrf");
    }

    #[test]
    fn rejects_invalid_names_and_paths() {
        assert_eq!(
            SessionCookies::new("Renkan", "/").err(),
            Some(CookieError::InvalidApplicationName)
        );
        assert_eq!(
            SessionCookies::new("", "/").err(),
            Some(CookieError::InvalidApplicationName)
        );
        assert_eq!(
            SessionCookies::new("renkan", "app").err(),
            Some(CookieError::InvalidPath)
        );
        assert_eq!(
            SessionCookies::new("renkan", "/app;x").err(),
            Some(CookieError::InvalidPath)
        );
    }

    #[test]
    fn issue_headers_carry_the_agreed_attributes() {
        let cookies = SessionCookies::new("renkan", "/").expect("cookies");
        let headers = cookies
            .issue_headers("session-token", "csrf-token", Duration::from_secs(604_800))
            .expect("headers");
        assert_eq!(
            headers[0],
            "__Host-renkan_session=session-token; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=604800"
        );
        assert_eq!(
            headers[1],
            "__Host-renkan_csrf=csrf-token; Path=/; Secure; SameSite=Lax; Max-Age=604800"
        );
        assert_eq!(
            cookies
                .issue_headers("bad;token", "csrf", Duration::ZERO)
                .err(),
            Some(CookieError::InvalidValue)
        );
    }

    #[test]
    fn clear_headers_expire_both_cookies() {
        let cookies = SessionCookies::new("renkan", "/app").expect("cookies");
        let headers = cookies.clear_headers();
        assert_eq!(
            headers[0],
            "__Secure-renkan_session=; Path=/app; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
        );
        assert_eq!(
            headers[1],
            "__Secure-renkan_csrf=; Path=/app; Secure; SameSite=Lax; Max-Age=0"
        );
    }
}
