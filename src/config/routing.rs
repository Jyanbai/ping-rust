use serde::Serialize;
use serde_yaml::Value;
use uuid::Uuid;

use super::schema::{ChainRule, RuleMasks, ServerRule};
use crate::chain_proxy::{ChainHop, ChainProxyState, RouteTarget};

#[derive(Serialize)]
struct ChainYaml {
    chain: Vec<Value>,
}

#[derive(Serialize)]
struct PoolYaml {
    pool: Vec<Value>,
}

pub(crate) fn chain_value(state: &ChainProxyState, id: Uuid) -> Value {
    let chain = state
        .chains
        .iter()
        .find(|chain| chain.id == id)
        .expect("validated chain");
    let hops = chain
        .hops
        .iter()
        .map(|hop| match hop {
            ChainHop::Node(node_id) => {
                let node = state
                    .nodes
                    .iter()
                    .find(|node| node.id == *node_id)
                    .expect("validated node");
                serde_yaml::to_value(&node.client).expect("client serializes")
            }
            ChainHop::Pool(pool_id) => {
                let pool = state
                    .pools
                    .iter()
                    .find(|pool| pool.id == *pool_id)
                    .expect("validated pool");
                let members = pool
                    .members
                    .iter()
                    .map(|node_id| {
                        let node = state
                            .nodes
                            .iter()
                            .find(|node| node.id == *node_id)
                            .expect("validated node");
                        serde_yaml::to_value(&node.client).expect("client serializes")
                    })
                    .collect();
                serde_yaml::to_value(PoolYaml { pool: members }).expect("pool serializes")
            }
        })
        .collect();
    serde_yaml::to_value(ChainYaml { chain: hops }).expect("chain serializes")
}

fn direct_value() -> Value {
    serde_yaml::from_str("protocol:\n  type: direct\n").expect("direct serializes")
}

fn rule_for_target(state: &ChainProxyState, masks: RuleMasks, target: &RouteTarget) -> ServerRule {
    let (action, client_chains) = match target {
        RouteTarget::Direct => ("allow", Some(direct_value())),
        RouteTarget::Block => ("block", None),
        RouteTarget::Chain(id) => ("allow", Some(chain_value(state, *id))),
        RouteTarget::RoundRobin(ids) => (
            "allow",
            Some(Value::Sequence(
                ids.iter().map(|id| chain_value(state, *id)).collect(),
            )),
        ),
    };
    ServerRule::Inline(ChainRule {
        masks,
        action: action.to_owned(),
        client_chains,
    })
}

pub(super) fn render_rules(state: &ChainProxyState) -> Vec<ServerRule> {
    if !state.enabled {
        return vec![ServerRule::Group("allow-all-direct".to_owned())];
    }
    let mut rules = state
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .map(|rule| {
            let masks = if rule.masks.len() == 1 {
                RuleMasks::One(rule.masks[0].clone())
            } else {
                RuleMasks::Many(rule.masks.clone())
            };
            rule_for_target(state, masks, &rule.target)
        })
        .collect::<Vec<_>>();
    rules.push(rule_for_target(
        state,
        RuleMasks::One("0.0.0.0/0".to_owned()),
        &state.default_route,
    ));
    rules.push(rule_for_target(
        state,
        RuleMasks::One("::/0".to_owned()),
        &state.default_route,
    ));
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_proxy::{parse_share_uri, ChainDefinition, ChainHop, ChainPool, RoutingRule};
    use std::{env, fs, path::Path, process::Command};

    fn fixture() -> ChainProxyState {
        let mut state = ChainProxyState::default();
        let first = parse_share_uri("socks5://127.0.0.1:18081#first").unwrap();
        let second = parse_share_uri("socks5://127.0.0.1:18082#second").unwrap();
        let third = parse_share_uri("socks5://127.0.0.1:18083#third").unwrap();
        let pool = ChainPool {
            id: Uuid::new_v4(),
            name: "exit pool".to_owned(),
            members: vec![second.id, third.id],
        };
        let chain_a = ChainDefinition {
            id: Uuid::new_v4(),
            name: "two hop".to_owned(),
            hops: vec![ChainHop::Node(first.id), ChainHop::Pool(pool.id)],
        };
        let chain_b = ChainDefinition {
            id: Uuid::new_v4(),
            name: "single hop".to_owned(),
            hops: vec![ChainHop::Node(third.id)],
        };
        state.nodes = vec![first, second, third];
        state.pools = vec![pool];
        state.chains = vec![chain_a.clone(), chain_b.clone()];
        state.rules = vec![
            RoutingRule {
                id: Uuid::new_v4(),
                name: "private".to_owned(),
                enabled: true,
                masks: vec!["192.168.0.0/16".to_owned(), "10.0.0.0/8".to_owned()],
                target: RouteTarget::Direct,
            },
            RoutingRule {
                id: Uuid::new_v4(),
                name: "blocked".to_owned(),
                enabled: true,
                masks: vec!["blocked.test".to_owned()],
                target: RouteTarget::Block,
            },
            RoutingRule {
                id: Uuid::new_v4(),
                name: "hostname".to_owned(),
                enabled: true,
                masks: vec!["*.example.com".to_owned()],
                target: RouteTarget::Chain(chain_a.id),
            },
            RoutingRule {
                id: Uuid::new_v4(),
                name: "round robin".to_owned(),
                enabled: true,
                masks: vec!["::1/128".to_owned()],
                target: RouteTarget::RoundRobin(vec![chain_a.id, chain_b.id]),
            },
        ];
        state.default_route = RouteTarget::Chain(chain_a.id);
        state.enabled = true;
        state.validate().unwrap();
        state
    }

    #[test]
    fn pinned_schema_accepts_full_v2_rule_shape() {
        let state = fixture();
        let rules = render_rules(&state);
        let rule_yaml = serde_yaml::to_string(&rules).unwrap();
        assert!(rule_yaml.contains("pool:"));
        assert!(rule_yaml.contains("client_chains:"));
        assert!(rule_yaml.contains("type: direct"));
        assert!(rule_yaml.contains("action: block"));
        assert!(rule_yaml.contains("::/0"));
        assert!(
            rule_yaml.find("192.168.0.0/16").unwrap() < rule_yaml.find("blocked.test").unwrap()
        );
        assert!(rule_yaml.find("blocked.test").unwrap() < rule_yaml.find("*.example.com").unwrap());

        let Some(binary) = env::var_os("PING_RUST_SHOES_E2E_BIN") else {
            return;
        };
        assert!(
            Path::new(&binary).is_file(),
            "pinned shoes binary is missing"
        );
        #[derive(Serialize)]
        struct Server {
            address: String,
            protocol: Value,
            rules: Vec<ServerRule>,
        }
        let server = Server {
            address: "127.0.0.1:18080".to_owned(),
            protocol: serde_yaml::from_str("type: socks\nudp_enabled: false\n").unwrap(),
            rules,
        };
        let yaml = serde_yaml::to_string(&[server]).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("chain-v2.yaml");
        fs::write(&path, yaml).unwrap();
        let output = Command::new(binary)
            .arg("--dry-run")
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
