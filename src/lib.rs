use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use pot::{from_slice, to_vec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use tls_helpers::privkey_from_base64;

type HmacSha256 = Hmac<Sha256>;

const MAX_PACKET_SIZE: usize = 1316; // SRT MTU size
const PACKET_HEADER_SIZE: usize = 13; // 1 byte flags + 8 bytes msg sequence + 4 bytes packet sequence
const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - PACKET_HEADER_SIZE;

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
    pub fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u64(self.sequence);
        buf.put_u64(self.timestamp);
        buf.put_u32(self.content.len() as u32);
        buf.extend_from_slice(&self.content);
        buf.put_u32(self.signature.len() as u32);
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() < 16 {
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
            content,
            timestamp,
            signature,
        })
    }

    pub fn to_packets(&self) -> Vec<BytesMut> {
        let full_data = self.to_bytes();
        let mut packets = Vec::new();
        let mut remaining = full_data.as_ref();
        let mut packet_sequence = 0u32;

        while !remaining.is_empty() {
            let chunk_size = remaining.len().min(MAX_PAYLOAD_SIZE);
            let (chunk, rest) = remaining.split_at(chunk_size);

            let mut packet = BytesMut::with_capacity(PACKET_HEADER_SIZE + chunk_size);
            packet.put_u8(if rest.is_empty() { 1 } else { 0 }); // flags
            packet.put_u64(self.sequence); // message sequence
            packet.put_u32(packet_sequence); // packet sequence
            packet.extend_from_slice(chunk);

            packets.push(packet);
            remaining = rest;
            packet_sequence += 1;
        }

        packets
    }
}

pub struct MessageSigner {
    signing_key: Vec<u8>,
    sequence: u64,
}

impl MessageSigner {
    pub fn new(base64_encoded_pem_key: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let private_key = privkey_from_base64(base64_encoded_pem_key)?;
        let mut hasher = Sha256::new();
        hasher.update(&private_key.0);
        let signing_key = hasher.finalize().to_vec();

        Ok(Self {
            signing_key,
            sequence: 0,
        })
    }

    pub fn sign<T: SignableMessage>(
        &mut self,
        message: &T,
    ) -> Result<SignedMessageEnvelope, Box<dyn Error>> {
        message.validate()?;
        let content = to_vec(message)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);

        let mut data = Vec::with_capacity(content.len() + 16);
        data.extend_from_slice(&sequence.to_be_bytes());
        data.extend_from_slice(&content);
        data.extend_from_slice(&timestamp.to_be_bytes());

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

    pub fn verify<T: SignableMessage>(
        &self,
        envelope: &SignedMessageEnvelope,
    ) -> Result<T, Box<dyn Error>> {
        let mut data = Vec::with_capacity(envelope.content.len() + 16);
        data.extend_from_slice(&envelope.sequence.to_be_bytes());
        data.extend_from_slice(&envelope.content);
        data.extend_from_slice(&envelope.timestamp.to_be_bytes());

        let mut mac = HmacSha256::new_from_slice(&self.signing_key)?;
        mac.update(&data);
        mac.verify_slice(&envelope.signature)?;

        let message: T = from_slice(&envelope.content)?;
        message.validate()?;
        Ok(message)
    }
}

struct PartialMessage {
    packets: Vec<(u32, BytesMut)>, // (packet_sequence, payload)
    total_size: usize,
    got_last: bool,
}

pub struct SignedMessageDemuxer {
    partial_messages: HashMap<u64, PartialMessage>,
}

impl SignedMessageDemuxer {
    pub fn new() -> Self {
        Self {
            partial_messages: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub enum DemuxError {
    InvalidPacket(String),
    MessageCorrupted {
        sequence: u64,
        reason: String,
    },
    EnvelopeParseError {
        sequence: u64,
        error: Box<dyn Error>,
    },
}

impl std::fmt::Display for DemuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemuxError::InvalidPacket(msg) => write!(f, "Invalid packet: {}", msg),
            DemuxError::MessageCorrupted { sequence, reason } => {
                write!(f, "Message {} corrupted: {}", sequence, reason)
            }
            DemuxError::EnvelopeParseError { sequence, error } => {
                write!(f, "Failed to parse message {}: {}", sequence, error)
            }
        }
    }
}

impl Error for DemuxError {}

#[derive(Debug)]
pub struct DemuxResult {
    pub messages: Vec<SignedMessageEnvelope>,
    pub errors: Vec<DemuxError>,
}

impl DemuxResult {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl SignedMessageDemuxer {
    pub fn process_packet(&mut self, packet: &[u8]) -> DemuxResult {
        let mut result = DemuxResult::new();

        if packet.len() < PACKET_HEADER_SIZE {
            result
                .errors
                .push(DemuxError::InvalidPacket("Packet too small".into()));
            return result;
        }

        let mut buf = &packet[..];
        let flags = buf.get_u8();
        let msg_sequence = buf.get_u64();
        let packet_sequence = buf.get_u32();
        let payload = BytesMut::from(&packet[PACKET_HEADER_SIZE..]);
        let is_last = (flags & 1) == 1;

        let message = self
            .partial_messages
            .entry(msg_sequence)
            .or_insert_with(|| PartialMessage {
                packets: Vec::new(),
                total_size: 0,
                got_last: false,
            });

        // Check for duplicate packet sequence
        if message
            .packets
            .iter()
            .any(|(seq, _)| *seq == packet_sequence)
        {
            result.errors.push(DemuxError::MessageCorrupted {
                sequence: msg_sequence,
                reason: format!("Duplicate packet sequence {}", packet_sequence),
            });
            self.partial_messages.remove(&msg_sequence);
            return result;
        }

        message.packets.push((packet_sequence, payload.clone()));
        message.total_size += payload.len();
        if is_last {
            message.got_last = true;
        }

        // Check all messages for completeness
        let mut complete_sequences = Vec::new();
        for (&sequence, message) in &mut self.partial_messages {
            if message.got_last {
                message.packets.sort_by_key(|(seq, _)| *seq);
                let expected_sequences: Vec<_> = (0..message.packets.len() as u32).collect();
                let actual_sequences: Vec<_> =
                    message.packets.iter().map(|(seq, _)| *seq).collect();
                if expected_sequences == actual_sequences {
                    complete_sequences.push(sequence);
                }
            }
        }

        // Process all complete messages
        for sequence in complete_sequences {
            if let Some(message) = self.partial_messages.remove(&sequence) {
                let mut combined = BytesMut::with_capacity(message.total_size);
                for (_, payload) in message.packets {
                    combined.extend_from_slice(&payload);
                }

                match SignedMessageEnvelope::from_bytes(&combined) {
                    Ok(envelope) => result.messages.push(envelope),
                    Err(e) => {
                        result
                            .errors
                            .push(DemuxError::EnvelopeParseError { sequence, error: e });
                    }
                }
            }
        }

        result
    }

    pub fn pending_message_count(&self) -> usize {
        self.partial_messages.len()
    }

    pub fn clear(&mut self) {
        self.partial_messages.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestMessage {
        data: String,
    }

    impl SignableMessage for TestMessage {}

    #[test]
    fn test_message_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut signer = MessageSigner::new(&std::env::var("PRIVKEY_PEM")?)?;
        let mut demuxer = SignedMessageDemuxer::new();

        // Create and sign multiple large messages
        let msg1 = TestMessage {
            data: "first".repeat(500),
        };
        let msg2 = TestMessage {
            data: "second".repeat(500),
        };

        let env1 = signer.sign(&msg1)?;
        let env2 = signer.sign(&msg2)?;

        // Split both into packets
        let packets1 = env1.to_packets();
        let packets2 = env2.to_packets();

        assert!(packets1.len() > 1);
        assert!(packets2.len() > 1);

        // Process packets, interleaving between messages
        for i in 0..packets1.len().max(packets2.len()) {
            if i < packets1.len() {
                let result = demuxer.process_packet(&packets1[i]);
                assert!(result.errors.is_empty());
                if i == packets1.len() - 1 {
                    assert_eq!(result.messages.len(), 1);
                    let decoded: TestMessage = signer.verify(&result.messages[0])?;
                    assert_eq!(decoded, msg1);
                } else {
                    assert!(result.messages.is_empty());
                }
            }

            if i < packets2.len() {
                let result = demuxer.process_packet(&packets2[i]);
                assert!(result.errors.is_empty());
                if i == packets2.len() - 1 {
                    assert_eq!(result.messages.len(), 1);
                    let decoded: TestMessage = signer.verify(&result.messages[0])?;
                    assert_eq!(decoded, msg2);
                } else {
                    assert!(result.messages.is_empty());
                }
            }
        }

        assert_eq!(demuxer.pending_message_count(), 0);
        Ok(())
    }

    #[test]
    fn test_error_handling() -> Result<(), Box<dyn Error>> {
        let mut demuxer = SignedMessageDemuxer::new();

        // Test invalid packet
        let result = demuxer.process_packet(&[1, 2, 3]);
        assert_eq!(result.messages.len(), 0);
        assert_eq!(result.errors.len(), 1);
        match &result.errors[0] {
            DemuxError::InvalidPacket(_) => (),
            _ => panic!("Expected InvalidPacket error"),
        }

        // Test duplicate packet sequence
        let mut signer = MessageSigner::new(&std::env::var("PRIVKEY_PEM")?)?;
        let msg = TestMessage {
            data: "test".repeat(500),
        };
        let env = signer.sign(&msg)?;
        let packets = env.to_packets();

        // Send first packet twice
        let result1 = demuxer.process_packet(&packets[0]);
        assert!(result1.errors.is_empty());
        let result2 = demuxer.process_packet(&packets[0]);
        assert_eq!(result2.errors.len(), 1);
        match &result2.errors[0] {
            DemuxError::MessageCorrupted { sequence, .. } => {
                assert_eq!(*sequence, env.sequence);
            }
            _ => panic!("Expected MessageCorrupted error"),
        }

        Ok(())
    }
}
