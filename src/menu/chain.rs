use super::*;
use crate::chain_proxy::{
    ChainDefinition, ChainHop, ChainPool, ChainProxyChange, ChainProxyState, RouteTarget,
    RoutingRule,
};
use uuid::Uuid;

pub(super) async fn menu() -> Result<()> {
    loop {
        let state = config::load_state()?.chain_proxy;
        println!("\n------------- Chain Proxy 2.0 -------------");
        println!("状态：{}", if state.enabled { "启用" } else { "禁用" });
        println!("默认路由：{}", target_label(&state, &state.default_route));
        let items = [
            (1, "节点管理"),
            (2, "Pool 管理"),
            (3, "Chain 管理"),
            (4, "路由规则"),
            (5, "默认路由"),
            (6, "启用 / 禁用"),
            (7, "测试节点 / Chain"),
            (8, "查看当前拓扑"),
            (0, "返回"),
        ];
        match select_keyed("", &items)? {
            0 => return Ok(()),
            1 => nodes_menu().await?,
            2 => pools_menu().await?,
            3 => chains_menu().await?,
            4 => rules_menu().await?,
            5 => change_default(&state).await?,
            6 => deployment::update_chain_proxy(ChainProxyChange::SetEnabled(!state.enabled))
                .await
                .map(|_| ())?,
            7 => test_menu(&state).await?,
            8 => print_topology(&state),
            _ => unreachable!(),
        }
    }
}

async fn test_menu(state: &ChainProxyState) -> Result<()> {
    match select_keyed(
        "测试",
        &[(1, "测试节点"), (2, "测试完整 Chain"), (0, "返回")],
    )? {
        0 => Ok(()),
        1 => test_chain_node().await,
        2 => {
            let Some(id) = choose_chain(state)? else {
                return Ok(());
            };
            let elapsed =
                crate::chain_proxy::test_chain(state, id, std::time::Duration::from_secs(10))
                    .await?;
            println!("完整 Chain 测试通过（{} ms）", elapsed.as_millis());
            Ok(())
        }
        _ => unreachable!(),
    }
}

fn text(prompt: &str, default: Option<&str>) -> Result<String> {
    let theme = ColorfulTheme::default();
    let input = Input::<String>::with_theme(&theme).with_prompt(prompt);
    Ok(match default {
        Some(value) => input.default(value.to_owned()).interact_text()?,
        None => input.interact_text()?,
    })
}

fn target_label(state: &ChainProxyState, target: &RouteTarget) -> String {
    match target {
        RouteTarget::Direct => "DIRECT".to_owned(),
        RouteTarget::Block => "BLOCK".to_owned(),
        RouteTarget::Chain(id) => state
            .chains
            .iter()
            .find(|chain| chain.id == *id)
            .map(|chain| chain.name.clone())
            .unwrap_or_else(|| "<missing>".to_owned()),
        RouteTarget::RoundRobin(ids) => format!(
            "轮询 [{}]",
            ids.iter()
                .map(|id| {
                    state
                        .chains
                        .iter()
                        .find(|chain| chain.id == *id)
                        .map(|chain| chain.name.as_str())
                        .unwrap_or("<missing>")
                })
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn numbered_indices(input: &str, count: usize, minimum: usize) -> Result<Vec<usize>> {
    let mut result = Vec::new();
    for part in input.split(',') {
        let number = part
            .trim()
            .parse::<usize>()
            .context("请输入逗号分隔的数字")?;
        if number == 0 || number > count {
            anyhow::bail!("编号 {number} 超出范围");
        }
        let index = number - 1;
        if !result.contains(&index) {
            result.push(index);
        }
    }
    if result.len() < minimum {
        anyhow::bail!("至少需要选择 {minimum} 项");
    }
    Ok(result)
}

async fn nodes_menu() -> Result<()> {
    loop {
        let state = config::load_state()?.chain_proxy;
        let items = [
            (1, "添加分享链接"),
            (2, "重命名"),
            (3, "测试"),
            (4, "删除"),
            (5, "查看"),
            (6, "选择出口"),
            (0, "返回"),
        ];
        match select_keyed("节点管理", &items)? {
            0 => return Ok(()),
            1 => add_chain_node().await?,
            2 => {
                if let Some(index) = select_chain_node(&state.nodes, "选择节点")? {
                    let node = &state.nodes[index];
                    let name = text("新名称", Some(&node.name))?;
                    deployment::update_chain_proxy(ChainProxyChange::RenameNode(node.id, name))
                        .await?;
                }
            }
            3 => test_chain_node().await?,
            4 => delete_chain_node().await?,
            5 => print_chain_nodes(&state.nodes, state.active().map(|node| node.id)),
            6 => select_chain_exit().await?,
            _ => unreachable!(),
        }
    }
}

fn select_member_ids(state: &ChainProxyState) -> Result<Vec<Uuid>> {
    if state.nodes.is_empty() {
        anyhow::bail!("请先添加节点");
    }
    for (index, node) in state.nodes.iter().enumerate() {
        println!(
            "{}) {} | {} | {}",
            index + 1,
            node.name,
            node.protocol_name(),
            node.address()
        );
    }
    let input = text("成员编号（逗号分隔）", None)?;
    Ok(numbered_indices(&input, state.nodes.len(), 1)?
        .into_iter()
        .map(|index| state.nodes[index].id)
        .collect())
}

async fn pools_menu() -> Result<()> {
    loop {
        let state = config::load_state()?.chain_proxy;
        println!("\nPool 管理：");
        for (index, pool) in state.pools.iter().enumerate() {
            let members = pool
                .members
                .iter()
                .filter_map(|id| state.nodes.iter().find(|node| node.id == *id))
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            println!("{}) {} [{}]", index + 1, pool.name, members);
        }
        let action = select_keyed(
            "",
            &[
                (1, "新建"),
                (2, "编辑成员"),
                (3, "重命名"),
                (4, "删除"),
                (0, "返回"),
            ],
        )?;
        match action {
            0 => return Ok(()),
            1 => {
                let name = text("Pool 名称", None)?;
                let members = select_member_ids(&state)?;
                deployment::update_chain_proxy(ChainProxyChange::AddPool(ChainPool {
                    id: Uuid::new_v4(),
                    name,
                    members,
                }))
                .await?;
            }
            2..=4 => {
                let labels = state
                    .pools
                    .iter()
                    .map(|pool| pool.name.as_str())
                    .collect::<Vec<_>>();
                let Some(index) = select_numbered("选择 Pool", &labels)? else {
                    continue;
                };
                let pool = &state.pools[index];
                let change = match action {
                    2 => ChainProxyChange::UpdatePool(ChainPool {
                        id: pool.id,
                        name: pool.name.clone(),
                        members: select_member_ids(&state)?,
                    }),
                    3 => ChainProxyChange::UpdatePool(ChainPool {
                        id: pool.id,
                        name: text("新名称", Some(&pool.name))?,
                        members: pool.members.clone(),
                    }),
                    4 => ChainProxyChange::DeletePool(pool.id),
                    _ => unreachable!(),
                };
                deployment::update_chain_proxy(change).await?;
            }
            _ => unreachable!(),
        }
    }
}

fn select_hops(state: &ChainProxyState) -> Result<Vec<ChainHop>> {
    let mut labels = state
        .nodes
        .iter()
        .map(|node| format!("节点：{}", node.name))
        .collect::<Vec<_>>();
    labels.extend(
        state
            .pools
            .iter()
            .map(|pool| format!("Pool：{}", pool.name)),
    );
    if labels.is_empty() {
        anyhow::bail!("请先添加节点或 Pool");
    }
    for (index, label) in labels.iter().enumerate() {
        println!("{}) {}", index + 1, label);
    }
    let input = text("按顺序输入 hop 编号（逗号分隔）", None)?;
    let indices = input
        .split(',')
        .map(|part| {
            let number = part
                .trim()
                .parse::<usize>()
                .context("请输入逗号分隔的数字")?;
            if number == 0 || number > labels.len() {
                anyhow::bail!("编号 {number} 超出范围");
            }
            Ok(number - 1)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(indices
        .into_iter()
        .map(|index| {
            if index < state.nodes.len() {
                ChainHop::Node(state.nodes[index].id)
            } else {
                ChainHop::Pool(state.pools[index - state.nodes.len()].id)
            }
        })
        .collect())
}

fn hop_label<'a>(state: &'a ChainProxyState, hop: &ChainHop) -> &'a str {
    match hop {
        ChainHop::Node(id) => state
            .nodes
            .iter()
            .find(|node| node.id == *id)
            .map(|node| node.name.as_str())
            .unwrap_or("<missing>"),
        ChainHop::Pool(id) => state
            .pools
            .iter()
            .find(|pool| pool.id == *id)
            .map(|pool| pool.name.as_str())
            .unwrap_or("<missing>"),
    }
}

async fn chains_menu() -> Result<()> {
    loop {
        let state = config::load_state()?.chain_proxy;
        println!("\nChain 管理：");
        for chain in &state.chains {
            println!("{}", chain.name);
            for (index, hop) in chain.hops.iter().enumerate() {
                println!("  {}. {}", index + 1, hop_label(&state, hop));
            }
        }
        let action = select_keyed(
            "",
            &[
                (1, "新建"),
                (2, "编辑 hops"),
                (3, "重命名"),
                (4, "删除"),
                (5, "追加 hop"),
                (6, "移除 hop"),
                (7, "hop 上移"),
                (8, "hop 下移"),
                (0, "返回"),
            ],
        )?;
        match action {
            0 => return Ok(()),
            1 => {
                let name = text("Chain 名称", None)?;
                let hops = select_hops(&state)?;
                deployment::update_chain_proxy(ChainProxyChange::AddChain(ChainDefinition {
                    id: Uuid::new_v4(),
                    name,
                    hops,
                }))
                .await?;
            }
            2..=8 => {
                let labels = state
                    .chains
                    .iter()
                    .map(|chain| chain.name.as_str())
                    .collect::<Vec<_>>();
                let Some(index) = select_numbered("选择 Chain", &labels)? else {
                    continue;
                };
                let chain = &state.chains[index];
                let change = match action {
                    2 => ChainProxyChange::UpdateChain(ChainDefinition {
                        id: chain.id,
                        name: chain.name.clone(),
                        hops: select_hops(&state)?,
                    }),
                    3 => ChainProxyChange::UpdateChain(ChainDefinition {
                        id: chain.id,
                        name: text("新名称", Some(&chain.name))?,
                        hops: chain.hops.clone(),
                    }),
                    4 => ChainProxyChange::DeleteChain(chain.id),
                    5 => {
                        let selected = select_hops(&state)?;
                        let mut hops = chain.hops.clone();
                        hops.extend(selected);
                        ChainProxyChange::UpdateChain(ChainDefinition {
                            id: chain.id,
                            name: chain.name.clone(),
                            hops,
                        })
                    }
                    6..=8 => {
                        let labels = chain
                            .hops
                            .iter()
                            .enumerate()
                            .map(|(index, hop)| {
                                format!("{}. {}", index + 1, hop_label(&state, hop))
                            })
                            .collect::<Vec<_>>();
                        let Some(position) = select_numbered("选择 hop", &labels)? else {
                            continue;
                        };
                        let mut hops = chain.hops.clone();
                        match action {
                            6 => {
                                hops.remove(position);
                            }
                            7 if position > 0 => hops.swap(position, position - 1),
                            8 if position + 1 < hops.len() => hops.swap(position, position + 1),
                            _ => continue,
                        }
                        ChainProxyChange::UpdateChain(ChainDefinition {
                            id: chain.id,
                            name: chain.name.clone(),
                            hops,
                        })
                    }
                    _ => unreachable!(),
                };
                deployment::update_chain_proxy(change).await?;
            }
            _ => unreachable!(),
        }
    }
}

fn select_target(state: &ChainProxyState) -> Result<Option<RouteTarget>> {
    Ok(
        match select_numbered("路由动作", &["DIRECT", "BLOCK", "Chain", "多 Chain 轮询"])? {
            None => None,
            Some(0) => Some(RouteTarget::Direct),
            Some(1) => Some(RouteTarget::Block),
            Some(2) => choose_chain(state)?.map(RouteTarget::Chain),
            Some(3) => {
                for (index, chain) in state.chains.iter().enumerate() {
                    println!("{}) {}", index + 1, chain.name);
                }
                let input = text("Chain 编号（至少两个，逗号分隔）", None)?;
                let ids = numbered_indices(&input, state.chains.len(), 2)?
                    .into_iter()
                    .map(|index| state.chains[index].id)
                    .collect();
                Some(RouteTarget::RoundRobin(ids))
            }
            _ => unreachable!(),
        },
    )
}

fn choose_chain(state: &ChainProxyState) -> Result<Option<Uuid>> {
    let labels = state
        .chains
        .iter()
        .map(|chain| chain.name.as_str())
        .collect::<Vec<_>>();
    Ok(select_numbered("选择 Chain", &labels)?.map(|index| state.chains[index].id))
}

fn parse_masks(input: &str) -> Result<Vec<String>> {
    let masks = input
        .split(',')
        .map(str::trim)
        .filter(|mask| !mask.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if masks.is_empty() {
        anyhow::bail!("至少需要一个 mask");
    }
    Ok(masks)
}

async fn rules_menu() -> Result<()> {
    loop {
        let state = config::load_state()?.chain_proxy;
        println!("\n路由规则：");
        for (index, rule) in state.rules.iter().enumerate() {
            println!(
                "{}) {} [{}] -> {}",
                index + 1,
                rule.name,
                rule.masks.join(", "),
                target_label(&state, &rule.target)
            );
        }
        let action = select_keyed(
            "",
            &[
                (1, "新建"),
                (2, "编辑名称"),
                (3, "编辑 masks"),
                (4, "编辑动作"),
                (5, "启用/禁用"),
                (6, "上移"),
                (7, "下移"),
                (8, "删除"),
                (0, "返回"),
            ],
        )?;
        match action {
            0 => return Ok(()),
            1 => {
                let name = text("规则名称", None)?;
                let masks = parse_masks(&text("Masks（逗号分隔）", None)?)?;
                let Some(target) = select_target(&state)? else {
                    continue;
                };
                deployment::update_chain_proxy(ChainProxyChange::AddRule(RoutingRule {
                    id: Uuid::new_v4(),
                    name,
                    enabled: true,
                    masks,
                    target,
                }))
                .await?;
            }
            2..=8 => {
                let labels = state
                    .rules
                    .iter()
                    .map(|rule| rule.name.as_str())
                    .collect::<Vec<_>>();
                let Some(index) = select_numbered("选择规则", &labels)? else {
                    continue;
                };
                let rule = &state.rules[index];
                let change = match action {
                    2 => Some(ChainProxyChange::UpdateRule(RoutingRule {
                        name: text("新名称", Some(&rule.name))?,
                        ..rule.clone()
                    })),
                    3 => Some(ChainProxyChange::UpdateRule(RoutingRule {
                        masks: parse_masks(&text(
                            "Masks（逗号分隔）",
                            Some(&rule.masks.join(", ")),
                        )?)?,
                        ..rule.clone()
                    })),
                    4 => select_target(&state)?.map(|target| {
                        ChainProxyChange::UpdateRule(RoutingRule {
                            target,
                            ..rule.clone()
                        })
                    }),
                    5 => Some(ChainProxyChange::UpdateRule(RoutingRule {
                        enabled: !rule.enabled,
                        ..rule.clone()
                    })),
                    6 if index > 0 => {
                        let mut rules = state.rules.clone();
                        rules.swap(index, index - 1);
                        Some(ChainProxyChange::SetRules(rules))
                    }
                    7 if index + 1 < state.rules.len() => {
                        let mut rules = state.rules.clone();
                        rules.swap(index, index + 1);
                        Some(ChainProxyChange::SetRules(rules))
                    }
                    8 => Some(ChainProxyChange::DeleteRule(rule.id)),
                    _ => None,
                };
                if let Some(change) = change {
                    deployment::update_chain_proxy(change).await?;
                }
            }
            _ => unreachable!(),
        }
    }
}

async fn change_default(state: &ChainProxyState) -> Result<()> {
    if let Some(target) = select_target(state)? {
        deployment::update_chain_proxy(ChainProxyChange::SetDefault(target)).await?;
    }
    Ok(())
}

fn print_topology(state: &ChainProxyState) {
    println!("\n节点：");
    for node in &state.nodes {
        println!(
            "  {} | {} | {}",
            node.name,
            node.protocol_name(),
            node.address()
        );
    }
    println!("Pools：");
    for pool in &state.pools {
        println!("  {}", pool.name);
    }
    println!("Chains：");
    for chain in &state.chains {
        println!("  {} ({} hops)", chain.name, chain.hops.len());
    }
    println!(
        "规则：{} 条；默认：{}",
        state.rules.len(),
        target_label(state, &state.default_route)
    );
    for rule in &state.rules {
        println!(
            "  {}：UDP-over-TCP {}",
            rule.name,
            if state.supports_udp_target(&rule.target) {
                "可用"
            } else {
                "不支持"
            }
        );
    }
    println!(
        "默认路由：UDP-over-TCP {}",
        if state.supports_udp_target(&state.default_route) {
            "可用"
        } else {
            "不支持"
        }
    );
}
