use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::Context;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};

use crate::util::{b64, b64_decode, wall_clock};

/// How many retired keys stay in the JWKS (and keep verifying) after a rotation.
pub const RETIRED_KEYS_KEPT: usize = 2;
const CURRENT_FILE: &str = "signing-key.pem";
const RETIRED_DIR: &str = "retired-keys";

/// One RS256 key pair and its public JWK.
struct KeyPair {
    private: RsaPrivateKey,
    signing: SigningKey<Sha256>,
    verifying: VerifyingKey<Sha256>,
    kid: String,
    jwk: Value,
}

impl KeyPair {
    fn new(private: RsaPrivateKey) -> Self {
        let public = private.to_public_key();
        let n = b64(public.n().to_bytes_be());
        let e = b64(public.e().to_bytes_be());
        // RFC 7638 JWK thumbprint as the key id.
        let thumbprint = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let kid = b64(Sha256::digest(thumbprint.as_bytes()));
        let jwk = json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e });
        Self { signing: SigningKey::new(private.clone()), verifying: VerifyingKey::new(public), private, kid, jwk }
    }

    fn generate() -> anyhow::Result<Self> {
        Ok(Self::new(RsaPrivateKey::new(&mut rand::thread_rng(), 2048).context("generating RSA key")?))
    }

    fn read(path: &Path) -> anyhow::Result<Self> {
        let pem = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let key = RsaPrivateKey::from_pkcs8_pem(&pem).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Self::new(key))
    }

    fn write(&self, path: &Path) -> anyhow::Result<()> {
        let pem = self.private.to_pkcs8_pem(LineEnding::LF)?;
        fs::write(path, pem.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

struct Ring {
    current: KeyPair,
    /// Newest first.
    retired: Vec<KeyPair>,
}

/// The signing keyring: one current RS256 key plus recently retired keys that still verify.
/// Persisted under the data dir as `signing-key.pem` and `retired-keys/<timestamp>-<kid>.pem`.
pub struct Keys {
    ring: RwLock<Ring>,
    dir: Option<PathBuf>,
}

/// Outcome of a key rotation.
pub struct Rotation {
    pub kid: String,
    pub retired_kids: Vec<String>,
}

impl Keys {
    /// An in-memory keyring with a fresh key (rotations are not persisted).
    pub fn generate() -> anyhow::Result<Self> {
        Ok(Self { ring: RwLock::new(Ring { current: KeyPair::generate()?, retired: vec![] }), dir: None })
    }

    /// Load the keyring from `dir`, creating (and persisting) a key if there is none.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(CURRENT_FILE);
        let current = if path.exists() {
            KeyPair::read(&path)?
        } else {
            tracing::info!("generating new signing key at {}", path.display());
            let key = KeyPair::generate()?;
            key.write(&path)?;
            key
        };
        let mut files: Vec<PathBuf> = fs::read_dir(dir.join(RETIRED_DIR))
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "pem"))
                    .collect()
            })
            .unwrap_or_default();
        // File names start with the retirement timestamp, so reverse order is newest first.
        files.sort();
        files.reverse();
        let retired = files.iter().take(RETIRED_KEYS_KEPT).map(|p| KeyPair::read(p)).collect::<anyhow::Result<_>>()?;
        Ok(Self { ring: RwLock::new(Ring { current, retired }), dir: Some(dir.to_path_buf()) })
    }

    pub fn kid(&self) -> String {
        self.ring.read().unwrap().current.kid.clone()
    }

    /// Generate a new current key; the old one is retired but stays in the JWKS.
    pub fn rotate(&self) -> anyhow::Result<Rotation> {
        let next = KeyPair::generate()?;
        let mut ring = self.ring.write().unwrap();
        if let Some(dir) = &self.dir {
            let retired_dir = dir.join(RETIRED_DIR);
            fs::create_dir_all(&retired_dir).with_context(|| format!("creating {}", retired_dir.display()))?;
            ring.current.write(&retired_dir.join(format!("{:012}-{}.pem", wall_clock(), ring.current.kid)))?;
            // Write-then-rename so a crash never leaves a half-written current key.
            let tmp = dir.join(format!("{CURRENT_FILE}.tmp"));
            next.write(&tmp)?;
            fs::rename(&tmp, dir.join(CURRENT_FILE)).context("replacing signing key")?;
        }
        let old = std::mem::replace(&mut ring.current, next);
        ring.retired.insert(0, old);
        let keep = RETIRED_KEYS_KEPT.min(ring.retired.len());
        for dropped in ring.retired.drain(keep..) {
            if let Some(dir) = &self.dir {
                let suffix = format!("-{}.pem", dropped.kid);
                if let Ok(entries) = fs::read_dir(dir.join(RETIRED_DIR)) {
                    for e in entries.flatten().filter(|e| e.file_name().to_string_lossy().ends_with(&suffix)) {
                        let _ = fs::remove_file(e.path());
                    }
                }
            }
        }
        tracing::info!("rotated signing key: {} is now current", ring.current.kid);
        Ok(Rotation {
            kid: ring.current.kid.clone(),
            retired_kids: ring.retired.iter().map(|k| k.kid.clone()).collect(),
        })
    }

    pub fn sign(&self, typ: &str, claims: &Value) -> String {
        let ring = self.ring.read().unwrap();
        let header = json!({ "alg": "RS256", "typ": typ, "kid": ring.current.kid });
        let input = format!("{}.{}", b64(header.to_string()), b64(claims.to_string()));
        let signature = ring.current.signing.sign(input.as_bytes());
        format!("{input}.{}", b64(signature.to_bytes()))
    }

    /// Verify the signature of a compact JWS against the current or a retired key,
    /// returning `(header, claims)`. Expiry and other claim checks are the caller's responsibility.
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
        let input = format!("{h}.{p}");
        let ring = self.ring.read().unwrap();
        let kid = header["kid"].as_str();
        let verified = std::iter::once(&ring.current)
            .chain(&ring.retired)
            .filter(|k| kid.is_none_or(|kid| kid == k.kid))
            .any(|k| k.verifying.verify(input.as_bytes(), &signature).is_ok());
        drop(ring);
        if !verified {
            return None;
        }
        let claims = serde_json::from_slice(&b64_decode(p)?).ok()?;
        Some((header, claims))
    }

    /// Public keys: the current key first, then retired keys.
    pub fn jwks(&self) -> Value {
        let ring = self.ring.read().unwrap();
        let keys: Vec<&Value> = std::iter::once(&ring.current).chain(&ring.retired).map(|k| &k.jwk).collect();
        json!({ "keys": keys })
    }
}

/// Decode a JWT payload without verifying it (used for request objects and hints).
pub fn decode_unverified(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&b64_decode(payload)?).ok()
}

/// Decode a JWT header without verifying the token.
pub fn decode_header_unverified(token: &str) -> Option<Value> {
    let header = token.split('.').next()?;
    serde_json::from_slice(&b64_decode(header)?).ok()
}

/// Verify an RS256 JWS against a client's JWK Set, returning its claims if any RSA key matches.
pub fn verify_rs256_with_jwks(token: &str, jwks: &Value) -> Option<Value> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    let header: Value = serde_json::from_slice(&b64_decode(h)?).ok()?;
    if header["alg"] != "RS256" {
        return None;
    }
    let signature = Signature::try_from(b64_decode(s)?.as_slice()).ok()?;
    let input = format!("{h}.{p}");
    let verified = jwks["keys"].as_array()?.iter().any(|jwk| {
        let usable = jwk["kty"] == "RSA"
            && jwk.get("use").is_none_or(|u| u == "sig")
            && (header.get("kid").is_none() || jwk.get("kid").is_none() || jwk["kid"] == header["kid"]);
        let key = || -> Option<RsaPublicKey> {
            let n = rsa::BigUint::from_bytes_be(&b64_decode(jwk["n"].as_str()?)?);
            let e = rsa::BigUint::from_bytes_be(&b64_decode(jwk["e"].as_str()?)?);
            RsaPublicKey::new(n, e).ok()
        };
        usable && key().is_some_and(|k| VerifyingKey::<Sha256>::new(k).verify(input.as_bytes(), &signature).is_ok())
    });
    verified.then(|| serde_json::from_slice(&b64_decode(p)?).ok()).flatten()
}
