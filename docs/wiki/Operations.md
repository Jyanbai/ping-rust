# 运维管理

## 服务管理

```bash
sudo ping-rust service status
sudo ping-rust service restart
sudo ping-rust service stop
sudo ping-rust service start
```

也可以进入 `prs → 5) 运行管理`。常规受管 profile 的新增、修改端口、删除非最后节点会尝试 Verified Hot Reload，并验证 MainPID、服务状态与监听集合；失败恢复旧配置和服务状态。

## 日志

```bash
sudo journalctl -u shoes.service -n 100 --no-pager
sudo journalctl -u shoes.service -f
```

## 更新

```bash
sudo ping-rust self-update
sudo ping-rust self-update --version v0.2.0
```

主菜单 `6) 更新` 是 Update Center：提供 ping-rust 自更新、已验证 shoes pin、显式 Release 安装和状态检查。已知较低 shoes Release 默认拒绝，需明确允许降级。自更新会验证 Release 来源、`SHA256SUMS` 与目标版本，使用原子替换并在失败时回滚。

## 备份和恢复

在 `prs → 9) 其他` 中选择备份或恢复。备份包含私钥、证书、密码、链式节点凭据和管理状态，应当按敏感文件保管。

## 端口与 BBR

“其他”菜单还提供 TCP/UDP 端口检查和 BBR 设置。BBR 会修改系统 sysctl，执行前应确认当前 VPS 内核支持。

## 卸载

```bash
sudo ping-rust uninstall
sudo ping-rust uninstall --purge
```

执行清除配置前先创建备份；敏感配置删除后可能无法恢复。

