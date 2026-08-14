# vpngate-socks

把 [VPN Gate](https://www.vpngate.net/ja/) 的日本家宽 / 非机房出口，变成 VPS 上一个可复制的 SOCKS5H 节点。

给偶尔用的。长期稳定请走自己的日本 VPS，别占志愿者带宽。

## 小白用法

在 Linux VPS 上（需要 root）：

```bash
curl -fsSL https://raw.githubusercontent.com/yayitinyu/vpngate/main/install.sh | sudo sh
```

装完会直接打印一行，复制到客户端即可：

```
socks5h://vg_a8f3k2m1:Xk9mP2qR7tL4nW8c@203.0.113.10:41287
```

- 用户名、密码、高位端口都是随机生成的，写在 `/etc/vpngate/node.conf`，重启不变
- 默认对外监听，并放行本机防火墙（ufw / firewalld / iptables）
- 默认用 systemd 常驻，掉线会自动换下一个志愿者

```bash
vpngate url      # 再看一次节点
vpngate stop     # 停
vpngate start    # 开
sudo /opt/vpngate/uninstall.sh
```

客户端必须选 **socks5h**（域名在代理侧解析），不要填 `socks5`。

云厂商安全组 / 防火墙面板如果默认拒绝入站，还要在面板里放行打印出来的那个 TCP 端口。

换一套新账号端口：

```bash
sudo /opt/vpngate/install.sh --rotate
```

## 它怎么走流量

```
你的软件 --socks5h://用户:密码@VPS:端口-->  VPS
                                              │  netns + OpenVPN
                                              ▼
                                         VPN Gate 日本家宽
```

VPS 自己的 SSH 不受影响。隧道断了不会从 VPS IP 漏出去。

## 进阶

```bash
vpngate list
vpngate status
vpngate doctor
sudo ./install.sh --no-service    # 不装 systemd
```

选服：Team Cymru 认家宽 / ISP / 学术 / 机房 / 筑波官方集群。默认丢掉机房和 `public-vpn-*`。

| 命令 | 作用 |
| --- | --- |
| `url` | 打印 `socks5h://…` |
| `init` | 生成账号端口并放行防火墙 |
| `start` / `stop` | 开 / 停（有 systemd 走服务） |
| `list` | 看当前能选哪些出口 |
| `--include-official` | 允许筑波官方机 |
| `--allow-dc` | 允许机房 IP |

## 注意

- 筑波大学学术项目，带宽是志愿者捐的。个人偶尔用可以，不要当 24/7 中继，更不要转售。
- **不是**隐私工具。志愿者和项目方看得到流量元数据。
- 志愿者 IP 经常被 Google / Cloudflare / 银行拉黑。
- `--watch` / systemd 换线后，**入口** URL 不变，**出口 IP** 会变。

## 许可证

MIT。VPN Gate 本身以官网为准。
