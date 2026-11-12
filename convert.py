#!/usr/bin/env python3
"""Convert a VLESS subscription to a Surge external policy list, never a profile."""
import argparse
import base64
import binascii
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor"))
try:
    import yaml
except ImportError:
    yaml = None

MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 20000


class ConversionError(Exception):
    pass


def scalar(value, label="参数"):
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise ConversionError(label + "必须为文本或数字")
    value = str(value)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConversionError(label + "包含控制字符")
    return value


def boolean(value):
    if value is True or str(value).lower() in ("true", "1"):
        return True
    if value is False or str(value).lower() in ("false", "0"):
        return False
    raise ConversionError("布尔参数必须是 true/false 或 1/0")


def quote(value):
    value = scalar(value)
    if not value or any(c in value for c in ',"\\#;') or value != value.strip() or " //" in value:
        return json.dumps(value, ensure_ascii=False)
    return value


def name_for(value):
    value = scalar(value, "节点名称").strip()
    value = value.translate(str.maketrans({",": "，", "=": "＝", '"': "＂", "\\": "＼", "#": "＃", ";": "；", "/": "／", "[": "［", "]": "］"}))
    return value or "VLESS"


def decode64(text):
    raw = re.sub(r"\s+", "", text)
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True).decode("utf-8-sig")
    except (ValueError, UnicodeError, binascii.Error):
        raise ConversionError("无法识别订阅格式；支持 Clash YAML/JSON、VLESS 链接和 Base64 链接订阅") from None


def parse_uri(uri):
    try:
        u = urlsplit(uri.strip())
        if u.scheme.lower() != "vless" or not u.hostname or not u.username or u.password is not None:
            raise ValueError()
        q = {k: values[-1] for k, values in parse_qs(u.query, keep_blank_values=True).items()}
        security = q.get("security", "none").lower()
        if security not in ("none", "tls", "reality"):
            raise ConversionError("不支持此 security 参数")
        node = {
            "name": unquote(u.fragment) or "VLESS",
            "type": "vless", "server": u.hostname, "port": u.port,
            "uuid": unquote(u.username), "network": q.get("type", "tcp"),
            "tls": security in ("tls", "reality"),
            "servername": q.get("sni", ""), "flow": q.get("flow", ""),
            "encryption": q.get("encryption", "none"),
        }
        if security == "reality":
            node["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
        if "fp" in q or "spx" in q:
            node["client-fingerprint"] = q.get("fp", "")
        if "alpn" in q:
            node["alpn"] = q["alpn"].split(",")
        if "allowInsecure" in q:
            node["skip-cert-verify"] = q["allowInsecure"]
        if "udp" in q:
            node["udp"] = q["udp"]
        if node["network"] == "ws":
            node["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q["host"]} if q.get("host") else {}}
        if node["network"] == "grpc":
            node["grpc-opts"] = {
                "grpc-service-name": q.get("serviceName", ""),
                "grpc-authority": q.get("authority", ""),
                "grpc-mode": q.get("mode", "gun"),
            }
        if "packetEncoding" in q and q["packetEncoding"] not in ("", "xudp"):
            raise ConversionError("仅支持 XUDP 封装")
        return node
    except (ValueError, TypeError):
        raise ConversionError("VLESS 链接的地址、端口或用户 ID 不完整") from None


def normalize(node):
    if not isinstance(node, dict):
        raise ConversionError("节点必须为对象")
    name = name_for(node.get("name", "VLESS"))
    server = scalar(node.get("server", ""), "服务器地址").strip()
    if not server or not re.fullmatch(r"[A-Za-z0-9_.:\-]+", server):
        raise ConversionError("服务器地址无效")
    if ":" in server:
        try:
            ipaddress.IPv6Address(server)
        except ValueError:
            raise ConversionError("IPv6 地址无效") from None
    try:
        port = int(str(node.get("port", "")))
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        raise ConversionError("端口必须介于 1 和 65535") from None
    uid = scalar(node.get("uuid", ""), "用户 ID")
    if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uid) and not 1 <= len(uid.encode("utf-8")) <= 30:
        raise ConversionError("用户 ID 必须为 UUID 或 1–30 字节的字符串")
    network = scalar(node.get("network", "tcp")).lower()
    if network not in ("tcp", "raw", "ws", "grpc"):
        raise ConversionError("不支持的传输方式：" + network)
    if str(node.get("encryption", "none")).lower() != "none":
        raise ConversionError("不支持 VLESS Encryption")
    for key in ("smux", "multiplex"):
        if key in node and (not isinstance(node[key], dict) or boolean(node[key].get("enabled", False))):
            raise ConversionError("不支持此节点的多路复用选项")
    if node.get("packet-encoding", "xudp") not in ("", "xudp"):
        raise ConversionError("仅支持 XUDP 封装")
    tls = boolean(node.get("tls", False))
    reality = node.get("reality-opts")
    if reality is not None and not isinstance(reality, dict):
        raise ConversionError("reality-opts 必须为对象")
    params = [("username", uid)]
    flow = scalar(node.get("flow", ""))
    if flow and flow not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
        raise ConversionError("不支持此 flow")
    if flow:
        if network not in ("raw", "tcp") or not (tls or reality is not None):
            raise ConversionError("Vision 需要 TCP + TLS/REALITY")
        params.append(("flow", flow))
    sni = scalar(node.get("servername", node.get("sni", "")))
    if sni:
        params.append(("sni", sni))
    notes = set()
    if "client-fingerprint" in node:
        notes.add("Surge 使用自己的 TLS 栈；未输出 client-fingerprint/fp/spx。")
    if reality is not None:
        if network == "ws":
            raise ConversionError("Surge 不支持 WebSocket + REALITY")
        key = scalar(reality.get("public-key", ""))
        try:
            if len(base64.b64decode(key + "=" * (-len(key) % 4), altchars=b"-_", validate=True)) != 32:
                raise ValueError()
        except (ValueError, binascii.Error):
            raise ConversionError("REALITY 公钥必须为 32 字节 Base64") from None
        if not sni:
            raise ConversionError("REALITY 缺少 servername/SNI")
        sid = scalar(reality.get("short-id", ""))
        if not re.fullmatch(r"[0-9a-fA-F]{0,16}", sid):
            raise ConversionError("REALITY short-id 必须为最多 16 位十六进制文本")
        params.extend((("reality-public-key", key), ("reality-short-id", sid)))
        if "support-x25519mlkem768" in reality:
            notes.add("未输出 support-x25519mlkem768；Surge 没有对应配置项，不保证此握手选项兼容。")
    elif tls:
        params.append(("tls", "true"))
    if network == "grpc" and not (tls or reality is not None):
        raise ConversionError("gRPC 需要 TLS 或 REALITY")
    if "skip-cert-verify" in node and reality is None:
        params.append(("skip-cert-verify", str(boolean(node["skip-cert-verify"])).lower()))
    if "alpn" in node:
        alpn = node["alpn"]
        if isinstance(alpn, list):
            alpn = ",".join(scalar(x) for x in alpn)
        params.append(("alpn", scalar(alpn)))
    if "udp" in node:
        params.append(("udp-relay", str(boolean(node["udp"])).lower()))
    if network == "ws":
        opts = node.get("ws-opts", {})
        if not isinstance(opts, dict) or not isinstance(opts.get("headers", {}), dict):
            raise ConversionError("ws-opts/headers 必须为对象")
        if opts.get("max-early-data") not in (None, "0", 0) or opts.get("early-data-header-name"):
            raise ConversionError("不支持 WebSocket early-data，未降级转换")
        params.extend((("ws", "true"), ("ws-path", opts.get("path", "/"))))
        headers = opts.get("headers", {})
        if headers:
            pairs = []
            for k, value in headers.items():
                k = scalar(k)
                if not re.fullmatch(r"[A-Za-z0-9-]+", k):
                    raise ConversionError("WebSocket Header 名称无效")
                value = scalar(value)
                if "|" in value:
                    raise ConversionError("WebSocket Header 值不能包含 |")
                pairs.append(k + ":" + value)
            params.append(("ws-headers", "|".join(pairs)))
    if network == "grpc":
        opts = node.get("grpc-opts", {})
        if not isinstance(opts, dict):
            raise ConversionError("grpc-opts 必须为对象")
        mode = opts.get("grpc-mode", "multi" if boolean(opts.get("multi-mode", False)) else "gun")
        if mode not in ("gun", "multi"):
            raise ConversionError("不支持此 gRPC mode")
        params.extend((("grpc", "true"), ("grpc-service-name", opts.get("grpc-service-name", ""))))
        params.append(("grpc-mode", mode))
        if opts.get("grpc-authority"):
            params.append(("grpc-authority", opts["grpc-authority"]))
    # Validate and quote every value before producing any output.
    tail = ", ".join(["vless", quote(server), str(port)] + [k + "=" + quote(v) for k, v in params])
    return name, tail, notes


def convert(text):
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ConversionError("订阅超过 8 MB，未处理")
    text = text.lstrip("\ufeff").strip()
    if not text:
        raise ConversionError("订阅内容为空")
    if not text.startswith(("vless://", "proxies:", "{", "[")) and ":" not in text:
        text = decode64(text).strip()
    warnings, notes, raw_nodes = [], set(), []
    # URI lists can contain other protocols; only VLESS is imported.
    if any(line.strip().startswith("vless://") for line in text.splitlines()):
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip().startswith("vless://"):
                continue
            try:
                raw_nodes.append(parse_uri(line))
            except ConversionError as e:
                warnings.append("第 %d 行：%s" % (i, e))
    else:
        if yaml is None:
            raise ConversionError("缺少 PyYAML，请先安装 requirements.txt")
        try:
            # BaseLoader preserves hexadecimal IDs and leading zeroes as strings.
            data = yaml.load(text, Loader=yaml.BaseLoader)
        except (yaml.YAMLError, RecursionError):
            raise ConversionError("YAML/JSON 语法错误，未输出任何文件") from None
        raw_nodes = data.get("proxies") if isinstance(data, dict) else data
        if not isinstance(raw_nodes, list):
            raise ConversionError("未找到 proxies 节点列表；请使用原始 Clash/Mihomo 订阅或 VLESS 链接订阅")
        raw_nodes = [n for n in raw_nodes if isinstance(n, dict) and str(n.get("type", "")).lower() == "vless"]
    if len(raw_nodes) > MAX_NODES:
        raise ConversionError("节点数量超过 20000，未处理")
    lines, names, seen, duplicates = [], set(), set(), 0
    for i, node in enumerate(raw_nodes, 1):
        try:
            name, tail, node_notes = normalize(node)
            # Identical connection settings are one node, even under different names.
            if tail in seen:
                duplicates += 1
                continue
            seen.add(tail)
            original, counter = name, 2
            while name in names:
                name = "%s (%d)" % (original, counter)
                counter += 1
            names.add(name)
            lines.append(name + " = " + tail)
            notes.update(node_notes)
        except (ConversionError, TypeError, ValueError, RecursionError) as e:
            reason = str(e) if isinstance(e, ConversionError) else "节点参数格式错误"
            warnings.append("第 %d 个 VLESS 节点：%s" % (i, reason))
    if not lines:
        detail = "；".join(warnings[:3])
        raise ConversionError("没有可转换的 VLESS 节点，原有文件未更改。" + detail)
    content = "# Surge VLESS policy list; generated locally. Contains credentials.\n" + "\n".join(lines) + "\n"
    return {"content": content, "count": len(lines), "warnings": warnings, "notes": sorted(notes), "duplicates": duplicates}


def read_source(source):
    source = source.strip()
    if source.startswith(("https://", "http://")):
        try:
            req = Request(source, headers={"User-Agent": "clash.meta", "Accept-Encoding": "identity"})
            with urlopen(req, timeout=30) as response:
                raw = response.read(MAX_BYTES + 1)
        except HTTPError as e:
            raise ConversionError("下载订阅失败：HTTP %d（未写入文件）" % e.code) from None
        except (URLError, TimeoutError, OSError, ValueError, UnicodeError):
            raise ConversionError("下载订阅失败，请检查链接、网络及系统代理（未写入文件）") from None
    elif source.startswith("vless://") or "\n" in source:
        raw = source.encode("utf-8")
    else:
        try:
            with Path(source).expanduser().open("rb") as f:
                raw = f.read(MAX_BYTES + 1)
        except (OSError, ValueError):
            raise ConversionError("请输入 HTTP(S) 订阅链接、vless:// 链接或已有订阅文件路径") from None
    if len(raw) > MAX_BYTES:
        raise ConversionError("订阅超过 8 MB，未处理")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeError:
        raise ConversionError("订阅不是 UTF-8 文本") from None


def write_list(path, content):
    path = Path(path).expanduser().absolute()
    if path.suffix.lower() != ".list":
        raise ConversionError("只允许导出 .list 文件，不会写入 .conf/.yaml 配置")
    if path.is_symlink() or path.exists() and not path.is_file():
        raise ConversionError("输出目标必须为普通文件")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".vless-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path


def applescript(script, *args):
    run = subprocess.run(["osascript", "-e", script, *args], capture_output=True, text=True)
    if run.returncode:
        raise KeyboardInterrupt()
    return run.stdout.strip()


def dialog_mode():
    source = applescript('''on run argv
      set resultDialog to display dialog "粘贴原始订阅链接或 vless:// 链接。\n仅导出节点列表，不修改 Surge 配置；链接不保存。" default answer "" with title "VLESS → Surge" buttons {"取消", "转换"} default button "转换" cancel button "取消" with hidden answer
      return text returned of resultDialog
    end run''')
    result = convert(read_source(source))
    summary = "可导出 %d 个节点，跳过 %d 个不兼容条目，合并 %d 个重复节点。" % (result["count"], len(result["warnings"]), result["duplicates"])
    details = "\n".join(result["warnings"][:6] + result["notes"])
    applescript('''on run argv
      display dialog (item 1 of argv) with title "转换预览" buttons {"取消", "选择保存位置"} default button "选择保存位置" cancel button "取消"
    end run''', summary + ("\n\n" + details if details else ""))
    output = applescript('''on run argv
      return POSIX path of (choose file name with prompt "保存节点列表（包含节点凭据，请勿上传公开仓库）" default name "vless.list")
    end run''')
    path = write_list(output, result["content"])
    applescript('''on run argv
      display dialog (item 1 of argv) with title "已导出" buttons {"完成"} default button "完成"
    end run''', summary + "\n\n" + str(path) + "\n\nSurge 的原有配置未改动。")


def main(argv=None):
    parser = argparse.ArgumentParser(description="提取 VLESS，导出 Surge .list；不修改配置，不记录订阅 URL。")
    parser.add_argument("--dialog", action="store_true", help="Mac 原生输入和保存对话框")
    parser.add_argument("--source-file", type=Path, help="读取本地 YAML/JSON 或链接订阅文件")
    parser.add_argument("--url-env", metavar="NAME", help="从指定环境变量读取 URL，避免命令历史记录")
    parser.add_argument("--output", type=Path, default=Path("output/vless.list"), help="输出 .list 路径")
    args = parser.parse_args(argv)
    try:
        if args.dialog:
            dialog_mode()
            return 0
        if args.source_file and args.url_env:
            raise ConversionError("--source-file 和 --url-env 不能同时使用")
        if args.source_file:
            source = str(args.source_file.expanduser().resolve())
        elif args.url_env:
            source = os.environ.get(args.url_env, "")
            if not source:
                raise ConversionError("指定的订阅环境变量为空")
        else:
            source = getpass.getpass("粘贴订阅链接（输入不回显），然后回车：")
        result = convert(read_source(source))
        if args.source_file and args.source_file.resolve() == args.output.resolve():
            raise ConversionError("不能覆盖输入文件")
        path = write_list(args.output, result["content"])
        print("已导出 %d 个 VLESS 节点至 %s" % (result["count"], path))
        print("跳过 %d 个条目，合并 %d 个重复节点。未修改 Surge 配置。" % (len(result["warnings"]), result["duplicates"]))
        for message in result["warnings"] + result["notes"]:
            print(message, file=sys.stderr)
        return 0
    except KeyboardInterrupt:
        return 130
    except (ConversionError, OSError) as e:
        message = str(e) if isinstance(e, ConversionError) else "文件读写失败，请检查目标路径和权限。"
        if args.dialog:
            try:
                applescript('''on run argv
                  display dialog (item 1 of argv) with title "未完成导出" buttons {"知道了"} default button "知道了" with icon caution
                end run''', message)
            except KeyboardInterrupt:
                pass
        else:
            print("错误：" + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
