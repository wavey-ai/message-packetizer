use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use pot::{from_slice, to_vec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use tls_helpers::privkey_from_base64;

type HmacSha256 = Hmac<Sha256>;

/// Trait for messages that can be signed
pub trait SignableMessage: Serialize + for<'de> Deserialize<'de> {
    /// Optional validation logic for the message content
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        Ok(()) // Default implementation does no validation
    }
}

/// A signed message envelope that can contain any SignableMessage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessageEnvelope {
    pub sequence: u64,
    pub content: Vec<u8>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl SignedMessageEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u64(self.sequence);
        buf.put_u64(self.timestamp);

        // Content length followed by content
        buf.put_u32(self.content.len() as u32);
        buf.extend_from_slice(&self.content);

        // Signature length followed by signature
        buf.put_u32(self.signature.len() as u32);
        buf.extend_from_slice(&self.signature);

        buf.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() < 16 {
            // minimum size for sequence + timestamp
            return Err("Buffer too small".into());
        }

        let mut buf = &bytes[..];

        let sequence = buf.get_u64();
        let timestamp = buf.get_u64();

        let content_len = buf.get_u32() as usize;
        if buf.remaining() < content_len {
            return Err("Invalid content length".into());
        }
        let content = buf[..content_len].to_vec();
        buf.advance(content_len);

        let signature_len = buf.get_u32() as usize;
        if buf.remaining() != signature_len {
            return Err("Invalid signature length".into());
        }
        let signature = buf[..signature_len].to_vec();

        Ok(SignedMessageEnvelope {
            sequence,
            timestamp,
            content,
            signature,
        })
    }
}

pub struct MessageSigner {
    signing_key: Vec<u8>,
    sequence: u64,
}

impl MessageSigner {
    /// Create a new MessageSigner from a Base64-encoded PEM key
    pub fn new(base64_encoded_pem_key: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let private_key = privkey_from_base64(base64_encoded_pem_key)?;

        // Derive a separate signing key using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&private_key.0);
        let signing_key = hasher.finalize().to_vec();

        Ok(Self {
            signing_key,
            sequence: 0,
        })
    }

    /// Sign a message that implements SignableMessage
    pub fn sign<T: SignableMessage>(
        &mut self,
        message: &T,
    ) -> Result<SignedMessageEnvelope, Box<dyn Error>> {
        // Validate the message first
        message.validate()?;

        // Encode the message
        let content = to_vec(message)?;

        // Get current timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Get next sequence
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);

        // Prepare data to sign
        let mut data = Vec::with_capacity(content.len() + 16); // +16 for sequence and timestamp
        data.extend_from_slice(&sequence.to_be_bytes());
        data.extend_from_slice(&content);
        data.extend_from_slice(&timestamp.to_be_bytes());

        // Create signature
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)?;
        mac.update(&data);
        let signature = mac.finalize().into_bytes();

        Ok(SignedMessageEnvelope {
            sequence,
            content,
            timestamp,
            signature: signature.to_vec(),
        })
    }

    /// Verify and decode a signed message
    pub fn verify<T: SignableMessage>(
        &self,
        envelope: &SignedMessageEnvelope,
    ) -> Result<T, Box<dyn Error>> {
        // Rebuild signed data
        let mut data = Vec::with_capacity(envelope.content.len() + 16);
        data.extend_from_slice(&envelope.sequence.to_be_bytes());
        data.extend_from_slice(&envelope.content);
        data.extend_from_slice(&envelope.timestamp.to_be_bytes());

        // Verify signature
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)?;
        mac.update(&data);
        mac.verify_slice(&envelope.signature)?;

        // Decode the message
        let message: T = from_slice(&envelope.content)?;

        // Validate the decoded message
        message.validate()?;

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example message type
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SimpleMessage {
        pub text: String,
        pub priority: Option<u8>,
        pub tags: Vec<String>,
    }

    impl SignableMessage for SimpleMessage {
        fn validate(&self) -> Result<(), Box<dyn Error>> {
            if let Some(priority) = self.priority {
                if priority > 5 {
                    return Err("Priority must be between 0 and 5".into());
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_message_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut signer = MessageSigner::new(&std::env::var("PRIVKEY_PEM")?)?;

        let original = SimpleMessage {
            text: "Hello".into(),
            priority: Some(3),
            tags: vec!["test".into()],
        };

        // Sign and encode
        let envelope = signer.sign(&original)?;
        let bytes = envelope.to_bytes();

        // Decode and verify
        let decoded_envelope = SignedMessageEnvelope::from_bytes(&bytes)?;
        let decoded: SimpleMessage = signer.verify(&decoded_envelope)?;

        assert_eq!(decoded, original);
        assert_eq!(decoded_envelope.sequence, envelope.sequence);
        Ok(())
    }
}
