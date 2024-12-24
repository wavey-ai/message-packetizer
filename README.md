# message-packetizer

A Rust library for signing, packetizing, and transmitting messages over SRT (Secure Reliable Transport). This library provides secure message signing and efficient packet handling for large messages that need to be split across multiple SRT packets.

## Features

- Message signing using HMAC-SHA256
- Automatic message sequence tracking
- Efficient packetization for large messages
- Automatic packet reassembly
- Support for custom message types via the `SignableMessage` trait
- Built-in error handling and message validation
- Designed for SRT's MTU size (1316 bytes)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
message-packetizer = "0.1.0"  # Replace with actual version
```

## Usage

### Basic Message Signing

```rust
use srt_message_signer::{MessageSigner, SignableMessage};
use serde::{Serialize, Deserialize};

// Define your custom message type
#[derive(Serialize, Deserialize)]
struct MyMessage {
    content: String,
}

// Implement SignableMessage for your type
impl SignableMessage for MyMessage {}

// Create a message signer
let mut signer = MessageSigner::new(&private_key_pem)?;

// Sign a message
let message = MyMessage {
    content: "Hello, World!".to_string()
};
let signed_envelope = signer.sign(&message)?;
```

### Message Verification

```rust
// Verify and decode a message
let decoded: MyMessage = signer.verify(&signed_envelope)?;
```

### Handling Large Messages with Packetization

```rust
// Create a demuxer for handling incoming packets
let mut demuxer = SignedMessageDemuxer::new();

// Split a large message into packets for transmission
let packets = signed_envelope.to_packets();

// Process received packets
for packet in received_packets {
    let result = demuxer.process_packet(&packet);

    // Handle any completed messages
    for message in result.messages {
        let decoded: MyMessage = signer.verify(&message)?;
        // Process the decoded message
    }

    // Handle any errors
    for error in result.errors {
        // Handle error
    }
}
```

### Custom Message Validation

```rust
#[derive(Serialize, Deserialize)]
struct ValidatedMessage {
    value: i32,
}

impl SignableMessage for ValidatedMessage {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.value < 0 {
            return Err("Value must be non-negative".into());
        }
        Ok(())
    }
}
```

## Technical Details

- Maximum packet size: 1316 bytes (SRT MTU)
- Packet header size: 13 bytes
- Maximum payload size per packet: 1303 bytes
- Uses HMAC-SHA256 for message signing
- Includes sequence numbers and timestamps

## Error Handling

The library provides detailed error types for various failure scenarios:

- `DemuxError::InvalidPacket`: Malformed or too small packets
- `DemuxError::MessageCorrupted`: Issues with packet sequencing or duplicates
- `DemuxError::EnvelopeParseError`: Problems parsing reassembled messages

## Safety and Security

- Automatic sequence number tracking prevents replay attacks
- Timestamps included in signatures
- Packet sequence validation ensures message integrity
- HMAC-SHA256 ensures message authenticity

## Performance Considerations

- Messages are automatically split into appropriately sized packets
- Efficient packet reassembly with minimal copying
- Uses `BytesMut` for optimal buffer management
- HashMap-based tracking of partial messages

## License

MIT
