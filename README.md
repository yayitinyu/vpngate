# vpngate-socks

把 [VPN Gate](https://www.vpngate.net/ja/) 的 **日本家宽 / 非机房** 出口接到 Linux VPS 上的 **SOCKS5H**。

给偶尔用的。长期稳定出口请直接用自己的日本 VPS，不要走志愿者。

```
应用 --socks5h://127.0.0.1:1080--> 本机 relay
                                      |
                                      v
                               netns vpngate
                                 OpenVPN → VPN Gate 志愿者
                                 (fail-closed：隧道断了就不会从 VPS IP 漏出去)
```

选服顺序：Team Cymru ASN 识别家宽 / ISP / 学术 / 机房 / 筑波官方集群 → 丢掉机房和 `public-vpn-*` → TCP 探活 → 按速度、ping、会话数排序。

## 一键安装 / 卸载

Debian / Ubuntu（需要 root）：

```bash
curl -fsSL https://raw.githubusercontent.com/yayitinyu/vpngate/main/install.sh | sudo sh
```

或先克隆再装：

```bash
git clone https://github.com/yayitinyu/vpngate.git
cd vpngate
sudo ./install.sh
```

装好后命令是 `vpngate`（包装进 `/usr/local/bin`，代码在 `/opt/vpngate`）。

```bash
sudo ./uninstall.sh
# 或
sudo /opt/vpngate/uninstall.sh
```

`install.sh` 会装 `python3` / `openvpn` / `iproute2` / `iptables`。默认不启 systemd。长期挂着用再加 `--with-service`。

## 依赖

Linux VPS，root，以及：

- Python 3.9+
- `openvpn`
- `iproute2`（`ip netns`）
- `iptables`
- `/dev/net/tun`

## 用法

```bash
sudo vpngate doctor
vpngate list
sudo vpngate up
```

另一个终端：

```bash
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me
# 必须是 socks5h（域名在代理侧解析），不要用 socks5
```

停：

```bash
sudo python3 -m vpngate down
# 或在 up 的终端 Ctrl+C
```

常用参数：

| 命令 | 作用 |
| --- | --- |
| `list` | 拉列表、分类、排序。默认不探活 |
| `up` | 选服、建 netns、连 OpenVPN、发布 SOCKS |
| `up --watch` | 隧道死后自动换下一个 |
| `rotate` | 丢掉当前出口再选 |
| `status` | 当前出口 IP / 进程 |
| `--include-official` | 允许筑波 `public-vpn-*`（机房向） |
| `--allow-dc` | 允许机房 / VPS |
| `--class residential` | 只要家宽 |
| `--socks-user U --socks-pass P` | SOCKS 用户名密码 |
| `--csv-file path` | 用缓存的 CSV，不访问官网 |

挂到 `0.0.0.0` **必须** 带账号密码，否则拒绝启动。

```bash
sudo python3 -m vpngate up --socks 0.0.0.0:1080 --socks-user me --socks-pass '…'
```

更稳妥的做法是只绑 `127.0.0.1`，外面再套一层 WireGuard / SSH。

## 分类

| class | 含义 | 默认 |
| --- | --- | --- |
| `residential` | SoftBank / KDDI / OCN / So-net / JCOM 等家宽 ASN | 用 |
| `isp` | IIJ / ARTERIA 等接入网（非机房） | 用 |
| `academic` | 大学 / SINET | 用 |
| `official` | `219.100.37.0/24`、`public-vpn-*`、AS36599 | 不用 |
| `datacenter` | Sakura / GMO / 云厂商 | 不用 |
| `unknown` | 认不出来 | 不用 |

列表接口：`https://www.vpngate.net/api/iphone/`

ASN：Team Cymru whois。Whois 失败时，`vpnNNNN` + `DESKTOP-…'s owner` 会按家宽启发式收下。

## systemd（可选）

```bash
sudo ./install.sh --with-service
sudo systemctl start vpngate
```

## 测试

```bash
python3 -m unittest discover -s tests -v
```

`up` / netns 只在 Linux 上验证。Windows 只能跑 `list` 和单元测试。

## 注意

- 这是筑波大学的学术项目，带宽是志愿者捐的。个人偶尔用可以；不要当 24/7 中继，更不要转售。
- VPN Gate **不是**隐私工具。对端志愿者和项目方看得到流量元数据。
- 志愿者 IP 经常被 Google / Cloudflare / 银行拉黑，连上 ≠ 目标站认这个 IP。
- 会话会掉。`--watch` 会换线，出口 IP 会变。
- 不要改 VPS 默认路由。本工具把 OpenVPN 关在 netns 里，SSH 不会被带走。

## 许可证

MIT。VPN Gate 本身的条款以官网为准。
