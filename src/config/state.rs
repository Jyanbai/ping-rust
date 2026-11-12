use serde::{Deserialize, Serialize};

use super::{ChainProxyState, Credentials, ManagedProfile, ManagedState};

// v0.2.1 ignores unknown top-level fields but rejects unknown credential variants
// inside profiles. Keep new protocols in extensions, never disguise them as
// legacy REALITY nodes. Positions preserve the runtime/state ordering.
#[derive(Serialize, Deserialize)]
pub(super) struct StateFile {
    schema_version: u8,
    profiles: Vec<ManagedProfile>,
    #[serde(default)]
    chain_proxy: ChainProxyState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    xhttp_profiles: Vec<PositionedProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sudoku_profiles: Vec<PositionedProfile>,
}

#[derive(Serialize, Deserialize)]
struct PositionedProfile {
    position: usize,
    profile: ManagedProfile,
}

impl From<ManagedState> for StateFile {
    fn from(state: ManagedState) -> Self {
        let mut profiles = Vec::new();
        let mut xhttp_profiles = Vec::new();
        let mut sudoku_profiles = Vec::new();
        for (position, profile) in state.profiles.into_iter().enumerate() {
            if matches!(profile.credentials, Credentials::VlessXhttpReality { .. }) {
                xhttp_profiles.push(PositionedProfile { position, profile });
            } else if matches!(profile.credentials, Credentials::VlessSudoku { .. }) {
                sudoku_profiles.push(PositionedProfile { position, profile });
            } else {
                profiles.push(profile);
            }
        }
        Self {
            schema_version: state.schema_version,
            profiles,
            chain_proxy: state.chain_proxy,
            xhttp_profiles,
            sudoku_profiles,
        }
    }
}

impl TryFrom<StateFile> for ManagedState {
    type Error = &'static str;

    fn try_from(mut state: StateFile) -> Result<Self, Self::Error> {
        // Validate each extension before merging so malformed ordering cannot
        // be hidden by sorting. Absolute positions include all extension types.
        let mut entries = Vec::new();
        for (extension, is_sudoku) in [(state.xhttp_profiles, false), (state.sudoku_profiles, true)]
        {
            let mut previous = None;
            for entry in extension {
                let valid_protocol = if is_sudoku {
                    matches!(entry.profile.credentials, Credentials::VlessSudoku { .. })
                } else {
                    matches!(
                        entry.profile.credentials,
                        Credentials::VlessXhttpReality { .. }
                    )
                };
                if !valid_protocol {
                    return Err("协议扩展中包含不匹配的节点");
                }
                if previous.is_some_and(|position| entry.position <= position) {
                    return Err("协议扩展中的节点位置无效");
                }
                previous = Some(entry.position);
                entries.push(entry);
            }
        }
        entries.sort_by_key(|entry| entry.position);
        let mut previous = None;
        for entry in entries {
            if previous == Some(entry.position) || entry.position > state.profiles.len() {
                return Err("协议扩展中的节点位置无效");
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
