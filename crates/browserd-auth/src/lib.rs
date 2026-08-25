//! Authentication and capability authorization primitives.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use browserd_core::{PrincipalId, SessionId, TenantId};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorBinding {
    #[serde(rename = "x5t#S256")]
    certificate_thumbprint: String,
}

impl ActorBinding {
    #[must_use]
    pub fn new(certificate_thumbprint: impl Into<String>) -> Self {
        Self {
            certificate_thumbprint: certificate_thumbprint.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    InvalidKeyConfiguration,
    SigningFailed,
    InvalidToken,
    UnknownKey,
    AlgorithmDenied,
    TokenExpired,
    TokenNotYetValid,
    TokenRevoked,
    ActorBindingRequired,
    ActorBindingMismatch,
    ScopeDenied,
    CapabilityBindingMismatch,
    UnknownToken,
    TokenConsumed,
    TokenAlreadyRegistered,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "authentication failed: {self:?}")
    }
}

impl std::error::Error for AuthError {}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    issuer: String,
    audience: String,
    allowed_algorithms: Vec<Algorithm>,
    clock_skew_seconds: i64,
    require_actor_binding: bool,
}

impl AuthConfig {
    #[must_use]
    pub fn new<I>(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        allowed_algorithms: I,
        clock_skew_seconds: u64,
        require_actor_binding: bool,
    ) -> Self
    where
        I: IntoIterator<Item = Algorithm>,
    {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            allowed_algorithms: allowed_algorithms.into_iter().collect(),
            clock_skew_seconds: i64::try_from(clock_skew_seconds).unwrap_or(i64::MAX),
            require_actor_binding,
        }
    }
}

#[derive(Clone, Debug)]
struct VerificationKey {
    algorithm: Algorithm,
    key: DecodingKey,
}

#[derive(Clone, Debug, Default)]
pub struct VerificationKeySet {
    keys: HashMap<String, VerificationKey>,
}

impl VerificationKeySet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_hmac(
        &mut self,
        key_id: impl Into<String>,
        algorithm: Algorithm,
        secret: &[u8],
    ) -> Result<(), AuthError> {
        let key_id = key_id.into();
        if key_id.trim().is_empty()
            || secret.is_empty()
            || !matches!(
                algorithm,
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
            )
        {
            return Err(AuthError::InvalidKeyConfiguration);
        }
        self.keys.insert(
            key_id,
            VerificationKey {
                algorithm,
                key: DecodingKey::from_secret(secret),
            },
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceClaims {
    iss: String,
    aud: String,
    #[serde(rename = "sub")]
    principal_id: PrincipalId,
    tenant_id: TenantId,
    scopes: BTreeSet<String>,
    jti: String,
    nbf: i64,
    exp: i64,
    cnf: Option<ActorBinding>,
}

impl ServiceClaims {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        principal_id: PrincipalId,
        tenant_id: TenantId,
        scopes: BTreeSet<String>,
        jti: impl Into<String>,
        not_before: i64,
        expires_at: i64,
        actor_binding: Option<ActorBinding>,
    ) -> Self {
        Self {
            iss: issuer.into(),
            aud: audience.into(),
            principal_id,
            tenant_id,
            scopes,
            jti: jti.into(),
            nbf: not_before,
            exp: expires_at,
            cnf: actor_binding,
        }
    }
}

#[derive(Clone)]
pub struct ServiceTokenSigner {
    key_id: String,
    algorithm: Algorithm,
    key: EncodingKey,
}

impl ServiceTokenSigner {
    #[must_use]
    pub fn new(key_id: impl Into<String>, algorithm: Algorithm, secret: &[u8]) -> Self {
        Self {
            key_id: key_id.into(),
            algorithm,
            key: EncodingKey::from_secret(secret),
        }
    }

    pub fn sign(&self, claims: &ServiceClaims) -> Result<String, AuthError> {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.key_id.clone());
        encode(&header, claims, &self.key).map_err(|_| AuthError::SigningFailed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipal {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    scopes: BTreeSet<String>,
    jti: String,
}

impl AuthenticatedPrincipal {
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    pub fn require_scope(&self, scope: &str) -> Result<(), AuthError> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(AuthError::ScopeDenied)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RevocationRegistry {
    revoked: Arc<Mutex<HashSet<String>>>,
}

impl RevocationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&self, jti: impl Into<String>) {
        lock(&self.revoked).insert(jti.into());
    }

    #[must_use]
    pub fn is_revoked(&self, jti: &str) -> bool {
        lock(&self.revoked).contains(jti)
    }
}

#[derive(Clone, Debug)]
pub struct ServiceTokenVerifier {
    config: AuthConfig,
    keys: VerificationKeySet,
    revocations: RevocationRegistry,
}

impl ServiceTokenVerifier {
    #[must_use]
    pub const fn new(
        config: AuthConfig,
        keys: VerificationKeySet,
        revocations: RevocationRegistry,
    ) -> Self {
        Self {
            config,
            keys,
            revocations,
        }
    }

    pub fn verify_at(
        &self,
        token: &str,
        actor_thumbprint: Option<&str>,
        now: i64,
    ) -> Result<AuthenticatedPrincipal, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(AuthError::AlgorithmDenied);
        }
        let key_id = header.kid.ok_or(AuthError::UnknownKey)?;
        let key = self.keys.keys.get(&key_id).ok_or(AuthError::UnknownKey)?;
        if key.algorithm != header.alg {
            return Err(AuthError::AlgorithmDenied);
        }
        let mut validation = Validation::new(key.algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "sub"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.leeway = 0;
        let decoded = decode::<ServiceClaims>(token, &key.key, &validation)
            .map_err(|_| AuthError::InvalidToken)?;
        let claims = decoded.claims;
        if claims.jti.trim().is_empty()
            || claims.scopes.iter().any(|scope| scope.trim().is_empty())
            || claims.exp <= claims.nbf
        {
            return Err(AuthError::InvalidToken);
        }
        if now > claims.exp.saturating_add(self.config.clock_skew_seconds) {
            return Err(AuthError::TokenExpired);
        }
        if now.saturating_add(self.config.clock_skew_seconds) < claims.nbf {
            return Err(AuthError::TokenNotYetValid);
        }
        if self.revocations.is_revoked(&claims.jti) {
            return Err(AuthError::TokenRevoked);
        }
        match (&claims.cnf, actor_thumbprint) {
            (Some(binding), Some(presented)) => {
                if !bool::from(
                    binding
                        .certificate_thumbprint
                        .as_bytes()
                        .ct_eq(presented.as_bytes()),
                ) {
                    return Err(AuthError::ActorBindingMismatch);
                }
            }
            (Some(_), None) => return Err(AuthError::ActorBindingRequired),
            (None, _) if self.config.require_actor_binding => {
                return Err(AuthError::ActorBindingRequired);
            }
            (None, _) => {}
        }
        Ok(AuthenticatedPrincipal {
            tenant_id: claims.tenant_id,
            principal_id: claims.principal_id,
            scopes: claims.scopes,
            jti: claims.jti,
        })
    }

    #[must_use]
    pub const fn revocations(&self) -> &RevocationRegistry {
        &self.revocations
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionCapabilityClaims {
    iss: String,
    aud: String,
    #[serde(rename = "sub")]
    principal_id: PrincipalId,
    tenant_id: TenantId,
    session_id: SessionId,
    session_incarnation: u64,
    policy_snapshot_id: String,
    scopes: BTreeSet<String>,
    jti: String,
    nbf: i64,
    exp: i64,
    cnf: Option<ActorBinding>,
}

impl SessionCapabilityClaims {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        session_id: SessionId,
        session_incarnation: u64,
        policy_snapshot_id: impl Into<String>,
        scopes: BTreeSet<String>,
        jti: impl Into<String>,
        not_before: i64,
        expires_at: i64,
        actor_binding: Option<ActorBinding>,
    ) -> Self {
        Self {
            iss: "browserd-capability".to_owned(),
            aud: "browserd-session".to_owned(),
            principal_id,
            tenant_id,
            session_id,
            session_incarnation,
            policy_snapshot_id: policy_snapshot_id.into(),
            scopes,
            jti: jti.into(),
            nbf: not_before,
            exp: expires_at,
            cnf: actor_binding,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CapabilityExpectation<'a> {
    pub tenant_id: &'a TenantId,
    pub principal_id: &'a PrincipalId,
    pub session_id: &'a SessionId,
    pub session_incarnation: u64,
    pub policy_snapshot_id: &'a str,
    pub required_scope: &'a str,
    pub actor_thumbprint: Option<&'a str>,
}

#[derive(Clone)]
pub struct SessionCapabilityCodec {
    key_id: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    clock_skew_seconds: i64,
}

impl SessionCapabilityCodec {
    #[must_use]
    pub fn new(key_id: impl Into<String>, secret: &[u8], clock_skew_seconds: u64) -> Self {
        Self {
            key_id: key_id.into(),
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            clock_skew_seconds: i64::try_from(clock_skew_seconds).unwrap_or(i64::MAX),
        }
    }

    pub fn issue(&self, claims: &SessionCapabilityClaims) -> Result<String, AuthError> {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.key_id.clone());
        encode(&header, claims, &self.encoding_key).map_err(|_| AuthError::SigningFailed)
    }

    pub fn verify_at(
        &self,
        token: &str,
        expectation: CapabilityExpectation<'_>,
        now: i64,
    ) -> Result<SessionCapabilityClaims, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        if header.alg != Algorithm::HS256 {
            return Err(AuthError::AlgorithmDenied);
        }
        if header.kid.as_deref() != Some(self.key_id.as_str()) {
            return Err(AuthError::UnknownKey);
        }
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["browserd-capability"]);
        validation.set_audience(&["browserd-session"]);
        validation.set_required_spec_claims(&["iss", "aud", "sub"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.leeway = 0;
        let claims = decode::<SessionCapabilityClaims>(token, &self.decoding_key, &validation)
            .map_err(|_| AuthError::InvalidToken)?
            .claims;
        if claims.jti.trim().is_empty()
            || claims.policy_snapshot_id.trim().is_empty()
            || claims.session_incarnation == 0
            || claims.exp <= claims.nbf
        {
            return Err(AuthError::InvalidToken);
        }
        if now > claims.exp.saturating_add(self.clock_skew_seconds) {
            return Err(AuthError::TokenExpired);
        }
        if now.saturating_add(self.clock_skew_seconds) < claims.nbf {
            return Err(AuthError::TokenNotYetValid);
        }
        if &claims.tenant_id != expectation.tenant_id
            || &claims.principal_id != expectation.principal_id
            || &claims.session_id != expectation.session_id
            || claims.session_incarnation != expectation.session_incarnation
            || claims.policy_snapshot_id != expectation.policy_snapshot_id
        {
            return Err(AuthError::CapabilityBindingMismatch);
        }
        if !claims.scopes.contains(expectation.required_scope) {
            return Err(AuthError::ScopeDenied);
        }
        match (&claims.cnf, expectation.actor_thumbprint) {
            (Some(binding), Some(presented)) => {
                if !bool::from(
                    binding
                        .certificate_thumbprint
                        .as_bytes()
                        .ct_eq(presented.as_bytes()),
                ) {
                    return Err(AuthError::ActorBindingMismatch);
                }
            }
            (Some(_), None) => return Err(AuthError::ActorBindingRequired),
            (None, _) => {}
        }
        Ok(claims)
    }
}

#[derive(Clone, Copy, Debug)]
struct OneTimeRecord {
    expires_at: i64,
    consumed: bool,
}

#[derive(Debug, Default)]
pub struct OneTimeJtiRegistry {
    records: Mutex<HashMap<String, OneTimeRecord>>,
}

impl OneTimeJtiRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, jti: impl Into<String>, expires_at: i64) -> Result<(), AuthError> {
        let jti = jti.into();
        if jti.trim().is_empty() {
            return Err(AuthError::InvalidToken);
        }
        let mut records = lock(&self.records);
        if records.contains_key(&jti) {
            return Err(AuthError::TokenAlreadyRegistered);
        }
        records.insert(
            jti,
            OneTimeRecord {
                expires_at,
                consumed: false,
            },
        );
        Ok(())
    }

    pub fn consume(&self, jti: &str, now: i64) -> Result<(), AuthError> {
        let mut records = lock(&self.records);
        let record = records.get_mut(jti).ok_or(AuthError::UnknownToken)?;
        if now >= record.expires_at {
            return Err(AuthError::TokenExpired);
        }
        if record.consumed {
            return Err(AuthError::TokenConsumed);
        }
        record.consumed = true;
        Ok(())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
