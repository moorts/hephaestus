use caps::{CapSet, Capability};
use color_eyre::{eyre::eyre, Result, Section};

pub fn check_caps() -> Result<()> {
    let has_cap_net_admin = caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN)?;
    let has_cap_net_raw = caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW)?;

    let mut missing_caps = Vec::new();

    if !has_cap_net_admin {
        missing_caps.push("CAP_NET_ADMIN");
    };
    if !has_cap_net_raw {
        missing_caps.push("CAP_NET_RAW");
    };

    if missing_caps.is_empty() {
        Ok(())
    } else {
        Err(eyre!(
            "Insufficient capabilities, missing: {:?}",
            missing_caps
        ))
        .suggestion("Use setcaps or run with root priviledges.")
    }
}
