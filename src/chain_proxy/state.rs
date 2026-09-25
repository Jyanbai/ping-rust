use std::collections::HashSet;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{validate_mask, validate_node_name, ChainNode};

pub const CHAIN_PROXY_STATE_VERSION: u8 = 2;
const MAX_NODES: usize = 512;
const MAX_POOLS: usize = 256;
const MAX_CHAINS: usize = 256;
const MAX_HOPS: usize = 32;
const MAX_RULES: usize = 512;
const MAX_MASKS: usize = 128;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainPool {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainHop {
    Node(Uuid),
    Pool(Uuid),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainDefinition {
    pub id: Uuid,
    pub name: String,
    pub hops: Vec<ChainHop>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum RouteTarget {
    #[default]
    Direct,
    Block,
    Chain(Uuid),
    RoundRobin(Vec<Uuid>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingRule {
    pub id: Uuid,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub masks: Vec<String>,
    pub target: RouteTarget,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainProxyState {
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing)]
    pub active_node: Option<Uuid>,
    #[serde(default)]
    pub nodes: Vec<ChainNode>,
    #[serde(default)]
    pub pools: Vec<ChainPool>,
    #[serde(default)]
    pub chains: Vec<ChainDefinition>,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    #[serde(default)]
    pub default_route: RouteTarget,
    #[serde(default, skip_serializing_if = "is_false")]
    pub legacy_layout: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn default_version() -> u8 {
    CHAIN_PROXY_STATE_VERSION
}

impl Default for ChainProxyState {
    fn default() -> Self {
        Self {
            version: CHAIN_PROXY_STATE_VERSION,
            enabled: false,
            active_node: None,
            nodes: Vec::new(),
            pools: Vec::new(),
            chains: Vec::new(),
            rules: Vec::new(),
            default_route: RouteTarget::Direct,
            legacy_layout: false,
        }
    }
}

impl ChainProxyState {
    pub fn validate(&self) -> Result<()> {
        if self.version != CHAIN_PROXY_STATE_VERSION {
            bail!("不支持的链式代理状态版本 {}", self.version);
        }
        if self.nodes.len() > MAX_NODES
            || self.pools.len() > MAX_POOLS
            || self.chains.len() > MAX_CHAINS
            || self.rules.len() > MAX_RULES
        {
            bail!("链式代理对象数量超过限制");
        }
        validate_unique_nodes(&self.nodes)?;
        validate_named(self.pools.iter().map(|pool| (pool.id, &pool.name)), "Pool")?;
        validate_named(
            self.chains.iter().map(|chain| (chain.id, &chain.name)),
            "Chain",
        )?;
        validate_named(
            self.rules.iter().map(|rule| (rule.id, &rule.name)),
            "路由规则",
        )?;

        let node_ids = self
            .nodes
            .iter()
            .map(|node| node.id)
            .collect::<HashSet<_>>();
        let pool_ids = self
            .pools
            .iter()
            .map(|pool| pool.id)
            .collect::<HashSet<_>>();
        let chain_ids = self
            .chains
            .iter()
            .map(|chain| chain.id)
            .collect::<HashSet<_>>();

        for pool in &self.pools {
            if pool.members.is_empty() {
                bail!("Pool {} 至少需要一个成员", pool.name);
            }
            if pool.members.len() > MAX_NODES {
                bail!("Pool {} 成员数量超过限制", pool.name);
            }
            if pool.members.iter().any(|id| !node_ids.contains(id)) {
                bail!("Pool {} 引用了不存在的节点", pool.name);
            }
            if pool.members.iter().collect::<HashSet<_>>().len() != pool.members.len() {
                bail!("Pool {} 包含重复成员", pool.name);
            }
        }
        for chain in &self.chains {
            if chain.hops.is_empty() || chain.hops.len() > MAX_HOPS {
                bail!("Chain {} 的 hop 数量无效", chain.name);
            }
            for hop in &chain.hops {
                match hop {
                    ChainHop::Node(id) if !node_ids.contains(id) => {
                        bail!("Chain {} 引用了不存在的节点", chain.name)
                    }
                    ChainHop::Pool(id) if !pool_ids.contains(id) => {
                        bail!("Chain {} 引用了不存在的 Pool", chain.name)
                    }
                    _ => {}
                }
            }
        }
        if let Some(id) = self.active_node {
            if !node_ids.contains(&id) {
                bail!("未找到链式代理节点 {id}");
            }
        }
        for rule in &self.rules {
            if rule.masks.is_empty() || rule.masks.len() > MAX_MASKS {
                bail!("路由规则 {} 的 mask 数量无效", rule.name);
            }
            for mask in &rule.masks {
                validate_mask(mask)?;
            }
            validate_target(&rule.target, &chain_ids)?;
        }
        validate_target(&self.default_route, &chain_ids)?;
        if self.legacy_layout
            && (!self.pools.is_empty()
                || !self.rules.is_empty()
                || self.chains.len() != 1
                || self.chains[0].name != "Legacy Default"
                || !matches!(self.chains[0].hops.as_slice(), [ChainHop::Node(_)])
                || self.default_route != RouteTarget::Chain(self.chains[0].id))
        {
            bail!("旧版链式代理兼容状态无效");
        }
        Ok(())
    }

    pub fn migrate_legacy(&mut self) -> Result<()> {
        if self.chains.is_empty() {
            let node_id = self
                .active_node
                .or_else(|| self.nodes.first().map(|node| node.id));
            if let Some(node_id) = node_id {
                self.require_node(node_id)?;
                let id = Uuid::new_v4();
                self.chains.push(ChainDefinition {
                    id,
                    name: "Legacy Default".to_owned(),
                    hops: vec![ChainHop::Node(node_id)],
                });
                self.default_route = RouteTarget::Chain(id);
                self.active_node = Some(node_id);
            } else if self.enabled {
                bail!("旧链式代理已启用，但没有节点");
            }
        }
        self.legacy_layout = true;
        self.validate()
    }

    pub fn active(&self) -> Option<&ChainNode> {
        let id = self.active_node.or_else(|| match self.default_route {
            RouteTarget::Chain(chain_id) => self
                .chains
                .iter()
                .find(|chain| chain.id == chain_id)
                .and_then(|chain| match chain.hops.as_slice() {
                    [ChainHop::Node(node_id)] => Some(*node_id),
                    _ => None,
                }),
            _ => None,
        });
        id.and_then(|id| self.nodes.iter().find(|node| node.id == id))
    }

    pub fn effective(&self) -> Option<&ChainNode> {
        self.enabled.then(|| self.active()).flatten()
    }

    pub fn supports_udp_target(&self, target: &RouteTarget) -> bool {
        match target {
            RouteTarget::Direct | RouteTarget::Block => true,
            RouteTarget::Chain(id) => self.chain_supports_udp(*id),
            RouteTarget::RoundRobin(ids) => ids.iter().all(|id| self.chain_supports_udp(*id)),
        }
    }

    fn chain_supports_udp(&self, id: Uuid) -> bool {
        let Some(chain) = self.chains.iter().find(|chain| chain.id == id) else {
            return false;
        };
        chain.hops.iter().all(|hop| match hop {
            ChainHop::Node(id) => self
                .nodes
                .iter()
                .find(|node| node.id == *id)
                .is_some_and(ChainNode::supports_udp_over_tcp),
            ChainHop::Pool(id) => {
                self.pools
                    .iter()
                    .find(|pool| pool.id == *id)
                    .is_some_and(|pool| {
                        pool.members.iter().all(|id| {
                            self.nodes
                                .iter()
                                .find(|node| node.id == *id)
                                .is_some_and(ChainNode::supports_udp_over_tcp)
                        })
                    })
            }
        })
    }

    pub fn apply(&mut self, change: ChainProxyChange) -> Result<()> {
        let preserve_legacy_layout = matches!(
            &change,
            ChainProxyChange::Select(_) | ChainProxyChange::SetEnabled(_)
        ) && self.pools.is_empty()
            && self.rules.is_empty()
            && (self.chains.is_empty()
                || (self.chains.len() == 1 && self.chains[0].name == "Legacy Default"));
        match change {
            ChainProxyChange::Add(node) => {
                validate_node_name(&node.name)?;
                if self.nodes.iter().any(|existing| {
                    existing.id == node.id || existing.name.eq_ignore_ascii_case(&node.name)
                }) {
                    bail!("链式节点名称或 ID 已存在：{}", node.name);
                }
                self.nodes.push(node);
            }
            ChainProxyChange::Select(id) => {
                self.require_node(id)?;
                self.active_node = Some(id);
                let chain_id = if let Some(chain) = self
                    .chains
                    .iter_mut()
                    .find(|chain| chain.name == "Legacy Default")
                {
                    chain.hops = vec![ChainHop::Node(id)];
                    chain.id
                } else {
                    let chain_id = Uuid::new_v4();
                    self.chains.push(ChainDefinition {
                        id: chain_id,
                        name: "Legacy Default".to_owned(),
                        hops: vec![ChainHop::Node(id)],
                    });
                    chain_id
                };
                self.default_route = RouteTarget::Chain(chain_id);
            }
            ChainProxyChange::SetEnabled(enabled) => {
                self.enabled = enabled;
            }
            ChainProxyChange::Delete(id) => {
                self.require_node(id)?;
                if let Some(pool) = self.pools.iter().find(|pool| pool.members.contains(&id)) {
                    bail!("节点 {} 仍被 Pool {} 引用", id, pool.name);
                }
                if let Some(chain) = self.chains.iter().find(|chain| {
                    chain
                        .hops
                        .iter()
                        .any(|hop| matches!(hop, ChainHop::Node(node_id) if *node_id == id))
                }) {
                    bail!("节点 {} 仍被 Chain {} 引用", id, chain.name);
                }
                self.nodes.retain(|node| node.id != id);
                if self.active_node == Some(id) {
                    self.active_node = None;
                    self.enabled = false;
                }
            }
            ChainProxyChange::RenameNode(id, name) => {
                validate_node_name(&name)?;
                let node = self
                    .nodes
                    .iter_mut()
                    .find(|node| node.id == id)
                    .ok_or_else(|| anyhow!("未找到节点 {id}"))?;
                node.name = name;
            }
            ChainProxyChange::AddPool(pool) => self.pools.push(pool),
            ChainProxyChange::UpdatePool(pool) => {
                let current = self
                    .pools
                    .iter_mut()
                    .find(|current| current.id == pool.id)
                    .ok_or_else(|| anyhow!("未找到 Pool {}", pool.id))?;
                *current = pool;
            }
            ChainProxyChange::DeletePool(id) => {
                let pool = self
                    .pools
                    .iter()
                    .find(|pool| pool.id == id)
                    .ok_or_else(|| anyhow!("未找到 Pool {id}"))?;
                if let Some(chain) = self.chains.iter().find(|chain| {
                    chain
                        .hops
                        .iter()
                        .any(|hop| matches!(hop, ChainHop::Pool(pool_id) if *pool_id == id))
                }) {
                    bail!("Pool {} 仍被 Chain {} 引用", pool.name, chain.name);
                }
                self.pools.retain(|pool| pool.id != id);
            }
            ChainProxyChange::AddChain(chain) => self.chains.push(chain),
            ChainProxyChange::UpdateChain(chain) => {
                let current = self
                    .chains
                    .iter_mut()
                    .find(|current| current.id == chain.id)
                    .ok_or_else(|| anyhow!("未找到 Chain {}", chain.id))?;
                *current = chain;
            }
            ChainProxyChange::DeleteChain(id) => {
                let chain = self
                    .chains
                    .iter()
                    .find(|chain| chain.id == id)
                    .ok_or_else(|| anyhow!("未找到 Chain {id}"))?;
                if let Some(rule) = self
                    .rules
                    .iter()
                    .find(|rule| target_contains(&rule.target, id))
                {
                    bail!("Chain {} 仍被路由规则 {} 引用", chain.name, rule.name);
                }
                if target_contains(&self.default_route, id) {
                    bail!("Chain {} 仍被默认路由引用", chain.name);
                }
                self.chains.retain(|chain| chain.id != id);
            }
            ChainProxyChange::AddRule(rule) => self.rules.push(rule),
            ChainProxyChange::UpdateRule(rule) => {
                let current = self
                    .rules
                    .iter_mut()
                    .find(|current| current.id == rule.id)
                    .ok_or_else(|| anyhow!("未找到路由规则 {}", rule.id))?;
                *current = rule;
            }
            ChainProxyChange::DeleteRule(id) => {
                if !self.rules.iter().any(|rule| rule.id == id) {
                    bail!("未找到路由规则 {id}");
                }
                self.rules.retain(|rule| rule.id != id);
            }
            ChainProxyChange::SetDefault(target) => self.default_route = target,
            ChainProxyChange::SetRules(rules) => self.rules = rules,
        }
        if !preserve_legacy_layout {
            self.legacy_layout = false;
        }
        self.validate()
    }

    fn require_node(&self, id: Uuid) -> Result<()> {
        if self.nodes.iter().any(|node| node.id == id) {
            Ok(())
        } else {
            bail!("未找到链式代理节点 {id}")
        }
    }
}

fn validate_unique_nodes(nodes: &[ChainNode]) -> Result<()> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for node in nodes {
        validate_node_name(&node.name)?;
        if !ids.insert(node.id) || !names.insert(node.name.to_ascii_lowercase()) {
            bail!("链式代理状态包含重复节点：{}", node.name);
        }
    }
    Ok(())
}

fn validate_named<'a>(objects: impl Iterator<Item = (Uuid, &'a String)>, kind: &str) -> Result<()> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for (id, name) in objects {
        validate_node_name(name)?;
        if !ids.insert(id) || !names.insert(name.to_ascii_lowercase()) {
            bail!("重复的 {kind} ID 或名称：{name}");
        }
    }
    Ok(())
}

fn validate_target(target: &RouteTarget, chain_ids: &HashSet<Uuid>) -> Result<()> {
    match target {
        RouteTarget::Chain(id) if !chain_ids.contains(id) => {
            bail!("路由引用了不存在的 Chain {id}")
        }
        RouteTarget::RoundRobin(ids) => {
            if ids.len() < 2 {
                bail!("RoundRobin 至少需要两条 Chain");
            }
            if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
                bail!("RoundRobin 不能包含重复 Chain");
            }
            if ids.iter().any(|id| !chain_ids.contains(id)) {
                bail!("RoundRobin 引用了不存在的 Chain");
            }
        }
        _ => {}
    }
    Ok(())
}

fn target_contains(target: &RouteTarget, id: Uuid) -> bool {
    match target {
        RouteTarget::Chain(chain_id) => *chain_id == id,
        RouteTarget::RoundRobin(ids) => ids.contains(&id),
        _ => false,
    }
}

#[derive(Clone, Debug)]
pub enum ChainProxyChange {
    Add(ChainNode),
    Select(Uuid),
    SetEnabled(bool),
    Delete(Uuid),
    RenameNode(Uuid, String),
    AddPool(ChainPool),
    UpdatePool(ChainPool),
    DeletePool(Uuid),
    AddChain(ChainDefinition),
    UpdateChain(ChainDefinition),
    DeleteChain(Uuid),
    AddRule(RoutingRule),
    UpdateRule(RoutingRule),
    DeleteRule(Uuid),
    SetDefault(RouteTarget),
    SetRules(Vec<RoutingRule>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_proxy::parse_share_uri;

    #[test]
    fn new_state_defaults_direct_and_does_not_serialize_legacy_selection() {
        let mut state = ChainProxyState::default();
        assert_eq!(state.default_route, RouteTarget::Direct);
        let node = parse_share_uri("socks5://127.0.0.1:1080#edge").unwrap();
        state.apply(ChainProxyChange::Add(node)).unwrap();
        assert_eq!(state.default_route, RouteTarget::Direct);
        assert!(state.active().is_none());
        assert!(!state.legacy_layout);
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"version\":2"));
        assert!(!json.contains("active_node"));
    }

    #[test]
    fn referenced_node_cannot_be_deleted() {
        let node = parse_share_uri("socks5://127.0.0.1:1080#edge").unwrap();
        let mut state = ChainProxyState::default();
        state.apply(ChainProxyChange::Add(node.clone())).unwrap();
        state.apply(ChainProxyChange::Select(node.id)).unwrap();
        let error = state
            .apply(ChainProxyChange::Delete(node.id))
            .unwrap_err()
            .to_string();
        assert!(error.contains("Legacy Default"));
    }

    #[test]
    fn legacy_state_migrates_to_a_default_chain_without_rewriting_until_save() {
        let node = parse_share_uri("socks5://127.0.0.1:1080#edge").unwrap();
        let node_id = node.id;
        let json = serde_json::json!({
            "enabled": true,
            "active_node": node_id,
            "nodes": [node],
        });
        let mut state: ChainProxyState = serde_json::from_value(json).unwrap();
        assert!(state.chains.is_empty());
        state.migrate_legacy().unwrap();
        assert!(state.enabled);
        assert_eq!(state.active().unwrap().id, node_id);
        assert!(matches!(state.default_route, RouteTarget::Chain(_)));
        assert_eq!(state.chains[0].hops, vec![ChainHop::Node(node_id)]);
    }

    #[test]
    fn disabled_legacy_selection_is_retained_after_save_and_reload() {
        let node = parse_share_uri("socks5://127.0.0.1:1080#edge").unwrap();
        let mut state: ChainProxyState = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "active_node": node.id,
            "nodes": [node]
        }))
        .unwrap();
        state.migrate_legacy().unwrap();
        let serialized = serde_json::to_string(&state).unwrap();
        let mut reloaded: ChainProxyState = serde_json::from_str(&serialized).unwrap();
        assert!(!reloaded.enabled);
        assert!(reloaded.legacy_layout);
        assert!(reloaded.active().is_some());
        reloaded.apply(ChainProxyChange::SetEnabled(true)).unwrap();
        assert!(reloaded.effective().is_some());
    }

    fn topology() -> ChainProxyState {
        let first = parse_share_uri("ss://YWVzLTEyOC1nY206cGFzcw==@127.0.0.1:10001#first").unwrap();
        let second = parse_share_uri("socks5://127.0.0.1:10002#second").unwrap();
        let third = parse_share_uri("ss://YWVzLTEyOC1nY206cGFzcw==@127.0.0.1:10003#third").unwrap();
        let pool = ChainPool {
            id: Uuid::new_v4(),
            name: "Exit".to_owned(),
            members: vec![first.id, third.id],
        };
        let chain = ChainDefinition {
            id: Uuid::new_v4(),
            name: "Via Pool".to_owned(),
            hops: vec![ChainHop::Node(second.id), ChainHop::Pool(pool.id)],
        };
        let alternate = ChainDefinition {
            id: Uuid::new_v4(),
            name: "Alternate".to_owned(),
            hops: vec![ChainHop::Node(first.id)],
        };
        ChainProxyState {
            nodes: vec![first, second, third],
            pools: vec![pool],
            chains: vec![chain.clone(), alternate.clone()],
            default_route: RouteTarget::RoundRobin(vec![chain.id, alternate.id]),
            ..ChainProxyState::default()
        }
    }

    #[test]
    fn validates_refs_uniqueness_and_limits() {
        let state = topology();
        state.validate().unwrap();
        let mut bad = state.clone();
        bad.pools[0].members.clear();
        assert!(bad.validate().unwrap_err().to_string().contains("至少"));
        let mut bad = state.clone();
        let duplicate = bad.pools[0].members[0];
        bad.pools[0].members.push(duplicate);
        assert!(bad.validate().unwrap_err().to_string().contains("重复"));
        let mut bad = state.clone();
        bad.pools[0].members[0] = Uuid::new_v4();
        assert!(bad.validate().unwrap_err().to_string().contains("不存在"));
        let mut bad = state.clone();
        bad.chains[0].hops.clear();
        assert!(bad.validate().unwrap_err().to_string().contains("hop"));
        let mut bad = state.clone();
        bad.chains[0].hops[1] = ChainHop::Pool(Uuid::new_v4());
        assert!(bad.validate().unwrap_err().to_string().contains("不存在"));
        let mut bad = state.clone();
        bad.default_route = RouteTarget::Chain(Uuid::new_v4());
        assert!(bad.validate().unwrap_err().to_string().contains("不存在"));
        let mut bad = state.clone();
        bad.default_route = RouteTarget::RoundRobin(vec![state.chains[0].id; 2]);
        assert!(bad.validate().unwrap_err().to_string().contains("重复"));
        let mut bad = state.clone();
        bad.chains[1].name = "via pool".to_owned();
        assert!(bad.validate().unwrap_err().to_string().contains("重复"));
        let mut bad = state.clone();
        bad.nodes[1].id = bad.nodes[0].id;
        assert!(bad.validate().unwrap_err().to_string().contains("重复"));
        let mut bad = state.clone();
        bad.chains[0].hops = vec![ChainHop::Node(state.nodes[0].id); MAX_HOPS + 1];
        assert!(bad.validate().unwrap_err().to_string().contains("hop"));
        let mut bad = state.clone();
        bad.rules = (0..=MAX_RULES)
            .map(|index| RoutingRule {
                id: Uuid::new_v4(),
                name: format!("rule-{index}"),
                enabled: true,
                masks: vec!["example.com".to_owned()],
                target: RouteTarget::Direct,
            })
            .collect();
        assert!(bad
            .validate()
            .unwrap_err()
            .to_string()
            .contains("数量超过限制"));
    }

    #[test]
    fn protects_referenced_objects_and_preserves_rule_order() {
        let mut state = topology();
        assert!(state
            .apply(ChainProxyChange::Delete(state.nodes[0].id))
            .unwrap_err()
            .to_string()
            .contains("Pool Exit"));
        assert!(state
            .apply(ChainProxyChange::DeletePool(state.pools[0].id))
            .unwrap_err()
            .to_string()
            .contains("Chain Via Pool"));
        assert!(state
            .apply(ChainProxyChange::DeleteChain(state.chains[0].id))
            .unwrap_err()
            .to_string()
            .contains("默认路由"));
        let first = RoutingRule {
            id: Uuid::new_v4(),
            name: "first".to_owned(),
            enabled: true,
            masks: vec!["10.0.0.0/8".to_owned()],
            target: RouteTarget::Direct,
        };
        let second = RoutingRule {
            id: Uuid::new_v4(),
            name: "second".to_owned(),
            enabled: true,
            masks: vec!["*.example.com".to_owned()],
            target: RouteTarget::Block,
        };
        state
            .apply(ChainProxyChange::SetRules(vec![
                first.clone(),
                second.clone(),
            ]))
            .unwrap();
        let json = serde_json::to_string(&state).unwrap();
        let reloaded: ChainProxyState = serde_json::from_str(&json).unwrap();
        assert_eq!(reloaded.rules, vec![first, second]);
    }

    #[test]
    fn udp_capability_requires_every_possible_hop() {
        let mut state = topology();
        let first = state.chains[0].id;
        let second = state.chains[1].id;
        assert!(!state.supports_udp_target(&RouteTarget::Chain(first)));
        assert!(state.supports_udp_target(&RouteTarget::Chain(second)));
        assert!(!state.supports_udp_target(&state.default_route));
        state.chains[0].hops.remove(0);
        assert!(state.supports_udp_target(&state.default_route));
        state.pools[0].members.push(state.nodes[1].id);
        assert!(!state.supports_udp_target(&RouteTarget::Chain(first)));
    }
}
