# 快速开始

## 首次安装

一键安装默认不询问协议或端口，会自动生成 VLESS-REALITY 所需的 UUID、X25519 密钥、short ID 和随机端口，然后输出 `vless://` 链接。将链接复制到 v2rayN 等客户端即可。

## 日常菜单

```bash
sudo prs
```

```text
1) 添加配置
2) 更改配置
3) 查看配置
4) 删除配置
5) 运行管理
6) 更新
7) 卸载
8) 帮助
9) 其他
10) 关于
0) 退出
```

添加配置时协议为连续 `1..=13`：11 为 SOCKS5、12 为实验性 Snell v3、13 为实验性 NaiveProxy；3 的 Shadowsocks 子菜单含 SS2022 + ShadowTLS v3。`9 → 1` 进入 Chain Proxy 2.0，`6` 进入 Update Center。

任意子菜单输入 `0` 返回。添加或查看配置成功后直接退出，便于复制分享链接。

## 快速添加

```bash
# 自动随机端口
sudo prs add reality --yes

# 指定端口
sudo prs add ss 8388
sudo prs add vless-ws-tls 443
sudo prs add socks5
sudo prs add snell

# 标准输出只保留分享链接
sudo prs add reality --yes --plain
```

## 查看链接

```bash
sudo prs info
sudo prs url
sudo prs qr
```

多个配置时可以追加配置名称或 UUID。

