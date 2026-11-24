//! 通过 Linux nfnetlink 在同一批次中校验规则集代数并按 handle 删除。
use std::{ffi::CString, io, time::Duration};

use anyhow::{bail, Context, Result};
use rustix::{
    io::Errno,
    net::{
        netlink::{self, SocketAddrNetlink},
        recvfrom, sendto, socket_with,
        sockopt::{set_socket_timeout, Timeout},
        AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType,
    },
};
use serde_json::Value;

// Linux UAPI: netlink.h, nfnetlink.h and nf_tables.h.
const NETLINK_ERROR: u16 = 2;
const REQUEST: u16 = 1;
const ACK: u16 = 4;
const BATCH_BEGIN: u16 = 16;
const BATCH_END: u16 = 17;
const NFTABLES: u16 = 10;
const DELETE_RULE: u16 = (NFTABLES << 8) | 8;
const NEW_GENERATION: u16 = (NFTABLES << 8) | 15;
const GET_GENERATION: u16 = (NFTABLES << 8) | 16;
const GENERATION_ID: u16 = 1;
const BATCH_GENERATION_ID: u16 = 1;
const RULE_TABLE: u16 = 1;
const RULE_CHAIN: u16 = 2;
const RULE_HANDLE: u16 = 3;
const SEQUENCE: u32 = 1;
const HEADER_LEN: usize = 16;
const NFGEN_LEN: usize = 4;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) fn generation() -> Result<u32> {
    let mut request = Vec::new();
    message(&mut request, GET_GENERATION, REQUEST, 0, 0, &[]);
    let reply = exchange(&request).context("无法读取 nftables 规则集代数")?;
    let (kind, payload) = parse_reply(&reply)?;
    if kind == NETLINK_ERROR {
        bail!(
            "查询 nftables 规则集代数失败：{}",
            io::Error::from_raw_os_error(ack_errno(payload)?)
        );
    }
    if kind != NEW_GENERATION {
        bail!("收到意外的 nftables 代数响应");
    }
    let mut attributes = payload
        .get(NFGEN_LEN..)
        .context("nftables 代数响应不完整")?;
    while let Some(header) = attributes.first_chunk::<4>() {
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        if len < header.len() || len.next_multiple_of(4) > attributes.len() {
            bail!("nftables 代数属性长度无效");
        }
        if u16::from_ne_bytes([header[2], header[3]]) & 0x3fff == GENERATION_ID {
            let bytes = attributes[4..len]
                .try_into()
                .context("nftables 代数长度无效")?;
            let id = u32::from_be_bytes(bytes);
            if id == 0 {
                bail!("内核未提供可用于条件删除的 nftables 代数");
            }
            return Ok(id);
        }
        attributes = &attributes[len.next_multiple_of(4)..];
    }
    bail!("nftables 响应缺少规则集代数")
}

pub(super) fn delete_rule(spec: &Value, handle: u64, generation: u32) -> Result<bool> {
    let family = match spec["family"].as_str() {
        Some("inet") => 1,
        Some("ip") => 2,
        Some("ip6") => 10,
        _ => bail!("nftables 规则地址族不支持条件删除"),
    };
    let table = CString::new(spec["table"].as_str().context("nftables 规则缺少表名")?)?;
    let chain = CString::new(spec["chain"].as_str().context("nftables 规则缺少链名")?)?;
    let mut batch = Vec::new();
    let mut attributes = Vec::new();
    attribute(
        &mut attributes,
        BATCH_GENERATION_ID,
        &generation.to_be_bytes(),
    );
    message(&mut batch, BATCH_BEGIN, REQUEST, 0, NFTABLES, &attributes);
    attributes.clear();
    attribute(&mut attributes, RULE_TABLE, table.as_bytes_with_nul());
    attribute(&mut attributes, RULE_CHAIN, chain.as_bytes_with_nul());
    attribute(&mut attributes, RULE_HANDLE, &handle.to_be_bytes());
    // 旧内核只确认批次里的规则消息。内核在处理完批次后发送规则的 ACK，
    // 提交失败时先发送批次错误。
    message(
        &mut batch,
        DELETE_RULE,
        REQUEST | ACK,
        family,
        0,
        &attributes,
    );
    message(&mut batch, BATCH_END, REQUEST, 0, NFTABLES, &[]);
    let reply = exchange(&batch).context("执行 nftables 条件删除失败")?;
    let (kind, payload) = parse_reply(&reply)?;
    if kind != NETLINK_ERROR {
        bail!("未收到 nftables 删除批次确认");
    }
    match ack_errno(payload)? {
        0 => Ok(true),
        errno if errno == Errno::RESTART.raw_os_error() => Ok(false),
        errno => Err(io::Error::from_raw_os_error(errno)).context("内核拒绝删除 nftables 规则"),
    }
}

fn attribute(bytes: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = 4 + data.len();
    bytes.extend_from_slice(&(len as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}

fn message(
    bytes: &mut Vec<u8>,
    kind: u16,
    flags: u16,
    family: u8,
    resource: u16,
    attributes: &[u8],
) {
    let len = (HEADER_LEN + NFGEN_LEN + attributes.len()) as u32;
    bytes.extend_from_slice(&len.to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&SEQUENCE.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&[family, 0]);
    bytes.extend_from_slice(&resource.to_be_bytes());
    bytes.extend_from_slice(attributes);
}

fn exchange(request: &[u8]) -> Result<Vec<u8>> {
    let socket = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(netlink::NETFILTER),
    )?;
    set_socket_timeout(&socket, Timeout::Send, Some(SOCKET_TIMEOUT))?;
    set_socket_timeout(&socket, Timeout::Recv, Some(SOCKET_TIMEOUT))?;
    let kernel = SocketAddrNetlink::new(0, 0);
    if sendto(&socket, request, SendFlags::empty(), &kernel)? != request.len() {
        bail!("未完整发送 nftables 请求");
    }
    let mut reply = vec![0; 8192];
    let (_, len, from) = recvfrom(&socket, reply.as_mut_slice(), RecvFlags::TRUNC)?;
    let peer = from.and_then(|addr| SocketAddrNetlink::try_from(addr).ok());
    if peer.is_none_or(|addr| addr.pid() != 0 || addr.groups() != 0) || len > reply.len() {
        bail!("无效的 nftables 内核响应");
    }
    reply.truncate(len);
    Ok(reply)
}

fn parse_reply(bytes: &[u8]) -> Result<(u16, &[u8])> {
    let header = bytes
        .first_chunk::<HEADER_LEN>()
        .context("nftables 响应头不完整")?;
    let len = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
    let kind = u16::from_ne_bytes([header[4], header[5]]);
    let sequence = u32::from_ne_bytes(header[8..12].try_into().unwrap());
    if sequence != SEQUENCE {
        bail!("nftables 响应序号与请求不匹配");
    }
    Ok((
        kind,
        bytes
            .get(HEADER_LEN..len)
            .context("nftables 响应长度无效")?,
    ))
}

fn ack_errno(payload: &[u8]) -> Result<i32> {
    let bytes = payload
        .first_chunk::<4>()
        .context("nftables 批次确认不完整")?;
    let status = i32::from_ne_bytes(*bytes);
    status
        .checked_neg()
        .filter(|errno| *errno >= 0)
        .context("nftables 批次状态无效")
}
