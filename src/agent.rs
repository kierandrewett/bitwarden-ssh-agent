//! The SSH agent protocol [`Session`] implementation.
//!
//! This is a *real* agent: private keys live only in this process's memory and
//! all signing happens in-process via RustCrypto. No key material is ever
//! written to disk, and agent-forwarding works exactly as with `ssh-agent`.

use anyhow::{anyhow, Context, Result};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::{Identity, SignRequest};
use ssh_agent_lib::proto::PublicCredential;
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};

use crate::bitwarden::SshKeyItem;
use crate::unlock::UnlockManager;

/// Signature flag bits from the agent protocol (draft-miller-ssh-agent § 3.6.1).
const RSA_SHA2_256: u32 = 0x02;
const RSA_SHA2_512: u32 = 0x04;

/// A single decrypted SSH key held in memory.
pub struct VaultKey {
    /// The parsed private key (zeroizes its own secret material on drop).
    private: PrivateKey,
    /// Cached public key data, used to answer identity/sign requests.
    public: KeyData,
    /// Human-readable comment (the vault item's name).
    comment: String,
}

impl VaultKey {
    /// Parse a vault SSH Key item into an in-memory key.
    ///
    /// Bitwarden always stores the private key as an OpenSSH PEM block. The
    /// `publicKey` field is authoritative for the comment shown to clients.
    pub fn from_item(item: &SshKeyItem) -> Result<Self> {
        let private = PrivateKey::from_openssh(item.ssh_key.private_key.as_bytes())
            .with_context(|| format!("parsing private key for vault item '{}'", item.name))?;

        if private.is_encrypted() {
            // Bitwarden stores keys unencrypted inside the (already encrypted)
            // vault, so this should not happen — but fail loudly if it does
            // rather than silently offering an unusable key.
            return Err(anyhow!(
                "private key for vault item '{}' is passphrase-encrypted; \
                 this is not supported",
                item.name
            ));
        }

        let public = private.public_key().key_data().clone();
        Ok(VaultKey {
            private,
            public,
            comment: item.name.clone(),
        })
    }

    fn identity(&self) -> Identity {
        Identity {
            credential: PublicCredential::Key(self.public.clone()),
            comment: self.comment.clone(),
        }
    }

    fn matches(&self, credential: &PublicCredential) -> bool {
        match credential {
            PublicCredential::Key(key) => key == &self.public,
            PublicCredential::Cert(_) => false,
        }
    }

    /// Sign `data`, honouring the client's requested RSA hash algorithm.
    fn sign(&self, data: &[u8], flags: u32) -> Result<Signature> {
        match self.private.key_data() {
            KeypairData::Rsa(keypair) => {
                // Modern OpenSSH always requests rsa-sha2-256/512; never sign
                // with the deprecated SHA-1 `ssh-rsa`. Default to SHA-512.
                let hash = if flags & RSA_SHA2_256 != 0 {
                    HashAlg::Sha256
                } else {
                    let _ = flags & RSA_SHA2_512; // 512 is our default anyway
                    HashAlg::Sha512
                };
                sign_rsa(keypair, data, hash)
            }
            _ => {
                use signature::Signer;
                self.private
                    .try_sign(data)
                    .context("signing with private key")
            }
        }
    }
}

/// Produce an RSA PKCS#1 v1.5 signature with the requested SHA-2 hash.
fn sign_rsa(
    keypair: &ssh_key::private::RsaKeypair,
    data: &[u8],
    hash: HashAlg,
) -> Result<Signature> {
    use rsa::pkcs1v15::SigningKey;
    use signature::{SignatureEncoding, Signer};
    use ssh_key::sha2::{Sha256, Sha512};

    let raw = match hash {
        HashAlg::Sha256 => {
            let signer = SigningKey::<Sha256>::try_from(keypair)
                .context("building RSA/SHA-256 signer")?;
            signer.try_sign(data).context("RSA/SHA-256 sign")?.to_vec()
        }
        // Default and explicit SHA-512.
        _ => {
            let signer = SigningKey::<Sha512>::try_from(keypair)
                .context("building RSA/SHA-512 signer")?;
            signer.try_sign(data).context("RSA/SHA-512 sign")?.to_vec()
        }
    };

    Signature::new(Algorithm::Rsa { hash: Some(hash) }, raw)
        .context("encoding RSA signature")
}

/// The agent session. Cheaply clonable — one is cloned per client connection,
/// all sharing the same unlock state and key cache.
#[derive(Clone)]
pub struct VaultAgent {
    unlock: UnlockManager,
}

impl VaultAgent {
    pub fn new(unlock: UnlockManager) -> Self {
        Self { unlock }
    }
}

/// Convert an [`anyhow::Error`] into an [`AgentError`] for the protocol layer.
fn agent_err(e: anyhow::Error) -> AgentError {
    AgentError::Other(e.into())
}

#[ssh_agent_lib::async_trait]
impl Session for VaultAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let keys = self.unlock.keys().await.map_err(agent_err)?;
        Ok(keys.iter().map(VaultKey::identity).collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let keys = self.unlock.keys().await.map_err(agent_err)?;
        let key = keys
            .iter()
            .find(|k| k.matches(&request.credential))
            .ok_or_else(|| agent_err(anyhow!("requested key not held by agent")))?;
        key.sign(&request.data, request.flags).map_err(agent_err)
    }
}
