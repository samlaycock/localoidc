use std::fs;
use std::path::Path;

use anyhow::Context;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};

use crate::util::{b64, b64_decode};

/// RS256 signing key plus its public JWK.
pub struct Keys {
    signing: SigningKey<Sha256>,
    verifying: VerifyingKey<Sha256>,
    pub kid: String,
    jwk: Value,
}

impl Keys {
    pub fn generate() -> anyhow::Result<Self> {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).context("generating RSA key")?;
        Ok(Self::from_private(key))
    }

    /// Load the PKCS#8 PEM key at `path`, creating (and persisting) a new one if missing.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let pem = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            let key = RsaPrivateKey::from_pkcs8_pem(&pem).with_context(|| format!("parsing {}", path.display()))?;
            return Ok(Self::from_private(key));
        }
        tracing::info!("generating new signing key at {}", path.display());
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).context("generating RSA key")?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let pem = key.to_pkcs8_pem(LineEnding::LF)?;
        fs::write(path, pem.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(Self::from_private(key))
    }

    pub fn from_private(key: RsaPrivateKey) -> Self {
        let public = key.to_public_key();
        let n = b64(public.n().to_bytes_be());
        let e = b64(public.e().to_bytes_be());
        // RFC 7638 JWK thumbprint as the key id.
        let thumbprint = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let kid = b64(Sha256::digest(thumbprint.as_bytes()));
        let jwk = json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e });
        Self {
            signing: SigningKey::new(key),
            verifying: VerifyingKey::new(public),
            kid,
            jwk,
        }
    }

    pub fn sign(&self, typ: &str, claims: &Value) -> String {
        let header = json!({ "alg": "RS256", "typ": typ, "kid": self.kid });
        let input = format!("{}.{}", b64(header.to_string()), b64(claims.to_string()));
        let signature = self.signing.sign(input.as_bytes());
        format!("{input}.{}", b64(signature.to_bytes()))
    }

    /// Verify the signature of a compact JWS, returning `(header, claims)`.
    /// Expiry and other claim checks are the caller's responsibility.
    pub fn verify(&self, token: &str) -> Option<(Value, Value)> {
        let mut parts = token.split('.');
        let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let header: Value = serde_json::from_slice(&b64_decode(h)?).ok()?;
        if header["alg"] != "RS256" {
            return None;
        }
        let signature = Signature::try_from(b64_decode(s)?.as_slice()).ok()?;
        self.verifying.verify(format!("{h}.{p}").as_bytes(), &signature).ok()?;
        let claims = serde_json::from_slice(&b64_decode(p)?).ok()?;
        Some((header, claims))
    }

    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.jwk] })
    }
}

/// Decode a JWT payload without verifying it (used for request objects and hints).
pub fn decode_unverified(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&b64_decode(payload)?).ok()
}
