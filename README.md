# mdscan

使用 Go 语言开发的网站/网络资产测绘 CLI。输入 IP 网段与端口范围，输出该范围内
mDNS 协议的资产信息（`ip` / `port` / `host` / 深度识别 `banner`），banner 深度
对齐参考示例（能解析出 `model=TS-X64`、`fwVer=5.2.9`、`accessType=https`、
`path=/` 等字段）。

## 构建

```bash
go build -o mdscan .
```

## 用法

```bash
mdscan -c 192.168.1.0/24 -p 1-10000 [-t 1.5s] [-j 256] [-f text|json] [-o out.txt] [--no-mdns] [--no-scan]
```

| 参数 | 说明 |
| --- | --- |
| `-c` | IP 网段：CIDR（`192.168.1.0/24`）或起止（`10.0.0.1-10.0.0.254`） |
| `-p` | 端口范围：`1-10000`、`80,443,5000` 或混合 |
| `-t` | mDNS 监听 / 连接超时，默认 `1.5s` |
| `-j` | TCP 扫描并发数，默认 `256` |
| `-f` | 输出格式：`text`（对齐示例）或 `json` |
| `-o` | 输出文件，默认 stdout |
| `--no-mdns` | 关闭 mDNS 组播发现 |
| `--no-scan` | 关闭 TCP 端口扫描 |

## 模块职责

| 文件 | 职责 |
| --- | --- |
| `main.go` | CLI 参数解析与流程编排：mDNS 发现 + 端口扫描 + 过滤 + 输出 |
| `internal/mdns/mdns.go` | 纯标准库 mDNS 客户端：构造 DNS 查询、解析响应（含域名压缩指针），提取 PTR/SRV/TXT/A/AAAA，并聚合为资产条目 |
| `internal/scanner/scanner.go` | IP 网段展开（CIDR/起止）与端口范围解析，以及并发 TCP connect 扫描 |
| `internal/probe/probe.go` | HTTP(S) 主动 banner 探测：`path=/`、`Server`、页面 `title` |
| `internal/output/output.go` | 聚合去重 + 文本输出（对齐参考示例）/ JSON 输出 |

## 输出示例（对齐参考格式）

```text
services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp http:
Name=slw-nas
IPv4=x.x.x.x
Hostname=slw-nas.local
TTL=10
path=/
445/tcp smb:
Name=slw-nas
IPv4=x.x.x.x
Hostname=slw-nas.local
TTL=10
5000/tcp qdiscover:
Name=slw-nas
IPv4=x.x.x.x
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=x.x.x.x
Hostname=slw-nas.local
TTL=10
model=Xserve
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=x.x.x.x
Hostname=slw-nas.local
TTL=10
answers:
PTR:
_afpovertcp._tcp.local
_device-info._tcp.local
_http._tcp.local
_qdiscover._tcp.local
_smb._tcp.local
_workstation._tcp.local
```