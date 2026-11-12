use serde::{Deserialize, Serialize};

use super::{ChainProxyState, Credentials, ManagedProfile, ManagedState};

// v0.2.1 ignores unknown top-level fields but rejects unknown credential variants
// inside profiles. Keep XHTTP profiles in an extension, never disguise them as
// legacy REALITY nodes. Positions preserve the runtime/state ordering.
#[derive(Serialize, Deserialize)]
pub(super) struct StateFile {
    schema_version: u8,
    profiles: Vec<ManagedProfile>,
    #[serde(default)]
    chain_proxy: ChainProxyState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    xhttp_profiles: Vec<XhttpProfile>,
}

#[derive(Serialize, Deserialize)]
struct XhttpProfile {
    position: usize,
    profile: ManagedProfile,
}

impl From<ManagedState> for StateFile {
    fn from(state: ManagedState) -> Self {
        let mut profiles = Vec::new();
        let mut xhttp_profiles = Vec::new();
        for (position, profile) in state.profiles.into_iter().enumerate() {
            if matches!(profile.credentials, Credentials::VlessXhttpReality { .. }) {
                xhttp_profiles.push(XhttpProfile { position, profile });
            } else {
                profiles.push(profile);
            }
        }
        Self {
            schema_version: state.schema_version,
            profiles,
            chain_proxy: state.chain_proxy,
            xhttp_profiles,
        }
    }
}

impl TryFrom<StateFile> for ManagedState {
    type Error = &'static str;

    fn try_from(mut state: StateFile) -> Result<Self, Self::Error> {
        let mut previous = None;
        for entry in state.xhttp_profiles {
            if !matches!(
                entry.profile.credentials,
                Credentials::VlessXhttpReality { .. }
            ) {
                return Err("XHTTP 扩展中包含非 XHTTP 节点");
            }
            if previous.is_some_and(|position| entry.position <= position)
                || entry.position > state.profiles.len()
            {
                return Err("XHTTP 扩展中的节点位置无效");
            }
            previous = Some(entry.position);
            state.profiles.insert(entry.position, entry.profile);
        }
        Ok(Self {
            schema_version: state.schema_version,
            profiles: state.profiles,
            chain_proxy: state.chain_proxy,
        })
    }
}
