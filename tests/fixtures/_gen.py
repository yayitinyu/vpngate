import base64
from pathlib import Path


def ovpn(ip: str, port: int = 443) -> str:
    return base64.b64encode(f"dev tun\nproto tcp\nremote {ip} {port}\n".encode()).decode()


rows = [
    (
        "public-vpn-1",
        "219.100.37.10",
        "3000000",
        "16",
        "220000000",
        "Japan",
        "JP",
        "80",
        "1000",
        "1",
        "1",
        "2weeks",
        "Daiyuu Nobori_ Japan. Academic Use Only.",
        "",
        ovpn("219.100.37.10"),
    ),
    (
        "vpn111",
        "126.1.2.3",
        "1400000",
        "8",
        "200000000",
        "Japan",
        "JP",
        "12",
        "1000",
        "1",
        "1",
        "2weeks",
        "DESKTOP-ABC's owner",
        "",
        ovpn("126.1.2.3"),
    ),
    (
        "sakura-node",
        "163.43.1.2",
        "900000",
        "-",
        "50000000",
        "Japan",
        "JP",
        "4",
        "1000",
        "1",
        "1",
        "2weeks",
        "sakura-vps",
        "",
        ovpn("163.43.1.2"),
    ),
    (
        "vpn333",
        "1.2.3.4",
        "100",
        "20",
        "1000",
        "United States",
        "US",
        "1",
        "1",
        "1",
        "1",
        "2weeks",
        "someone",
        "",
        ovpn("1.2.3.4"),
    ),
]
header = (
    "HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
    "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
)
lines = ["*vpn_servers", "#" + header]
for row in rows:
    lines.append(",".join(row))
lines.append("*")
path = Path(__file__).with_name("servers.csv")
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(path)
