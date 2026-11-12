# VLESS → Surge 节点列表转换器

运行时粘贴订阅链接，提取 VLESS 节点，导出 Surge 可用的 `vless.list`。**不读取、修改或自动重载你的 Surge 配置，不保存订阅链接。**

这不是 `.sgmodule`：Surge 官方模块不能修改 `[Proxy]` 和 `[Proxy Group]`。这里使用独立转换工具生成节点列表，供 Surge 的外部策略组 `policy-path` 引用。

## Mac 双击使用

1. 下载或克隆本项目，放在一个固定目录。需要 Python 3.9+ 和 pip；首次使用安装 PyYAML，之后无需重复安装。
2. 双击 **`导出VLESS.command`**。如果下载后没有执行权限，先运行 `chmod +x 导出VLESS.command`。
3. 粘贴原始订阅链接（输入隐藏），点击“转换”。也可以粘贴单个 `vless://` 链接。
4. 查看转换数量、不兼容条目及说明，选择 `.list` 保存位置。

链接只保留在当前进程内存中，不写入源码、配置或日志。下载只请求该订阅地址及其服务器指定的跳转地址，不使用第三方转换服务。默认使用 `clash.meta` User-Agent，尽量获取包含 VLESS 的 Clash 原始订阅；请避免使用已经过滤掉 VLESS 的旧版 Surge 转换订阅。

取消或转换失败时，不覆盖已有输出。重复导出到同一位置，会替换节点列表，不累积重复节点。

## 命令行

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

# 交互输入订阅链接，不回显，也不会进入 shell 命令历史
python3 convert.py --output output/vless.list

# 从本地订阅文件导出
python3 convert.py --source-file /path/to/subscription.yaml --output output/vless.list

# 已有环境变量时，按变量名读取（不输出 URL）
python3 convert.py --url-env SUBSCRIPTION_URL --output output/vless.list

# 测试
python3 -m unittest discover -s tests -v
```

如果 Mac 上有自己的 Python，可用 `VLESS_PYTHON=/path/to/python3 ./导出VLESS.command`。工具默认使用 `/usr/bin/python3`；若该解释器不存在或未安装 pip，请先按上面的命令行步骤配置 Python。

## 在 Surge 中使用导出的文件

工具只导出节点，不自动添加策略组。你可以自行在 Surge 文本配置里引用，例如把 `vless.list` 和当前配置放在同一目录：

```ini
[Proxy Group]
VLESS订阅 = select, policy-path=vless.list
```

再将 `VLESS订阅` 添加到你现有选择组中。列表更新后重新载入配置；本地列表不会自己下载上游订阅，需要再次运行本工具。

Mac 与 iOS 共用时，可以把 `.list` 存入 Surge 的 iCloud 配置目录，在支持 VLESS 的客户端中引用。若手动把内容粘贴进 `[Proxy]`，不要重复粘贴段标题：输出本身不含 `[Proxy]`。

**把工具源码上传 GitHub 即可；真实导出的列表包含 UUID、公钥等节点信息，不要上传到公开仓库。** `.gitignore` 已排除输出列表、YAML 订阅、依赖目录与缓存；示例文件只使用虚构参数。

## 输入与兼容范围

支持：

- HTTP(S) 订阅链接。
- Clash/Mihomo YAML 或 JSON 的 `proxies` 列表，以及节点数组。
- 单个或多行 `vless://` 分享链接。
- Base64 / URL-safe Base64 编码的链接订阅。
- TCP/RAW、WebSocket、gRPC；按 Surge 官方组合支持 TLS、REALITY、XTLS Vision。
- `udp: false`、SNI、REALITY 公钥及 short-id、WebSocket 路径和 Headers、gRPC serviceName/authority/mode、ALPN。

非 VLESS 节点会被忽略。XHTTP、HTTPUpgrade、mKCP、VLESS Encryption、不兼容的 Vision 组合、其他 UDP 封装及 WebSocket early-data 会跳过并报告；没有可用节点时不写文件。

`client-fingerprint` / `fp` / `spx` 不输出，Surge 使用自身的 TLS 栈。`support-x25519mlkem768` 没有对应 Surge 配置项，会明确提示未输出；转换成功不等于服务端握手一定兼容。工具按官方 Surge 语法生成，非官方修改版是否兼容需实际验证。官方文档标注 VLESS 需要 Surge iOS 6.0.0+ / Mac 6.12.0+。

## 放到 GitHub

把本目录中的 `convert.py`、`导出VLESS.command`、`requirements.txt`、`README.md`、`tests/`、`examples/`、`.gitignore` 和 `.github/` 上传到你的仓库即可。不要上传 `vendor/`、`output/` 或真实订阅。

附带的 GitHub Actions 仅运行虚构参数的测试，不获取订阅、不生成真实节点、不需要 Secrets。

## 官方依据

- [Surge 模块限制](https://manual.nssurge.com/profile/module.html)
- [VLESS 参数与支持组合](https://manual.nssurge.com/policies/vless.html)
- [外部策略列表 policy-path](https://manual.nssurge.com/policy-groups/policy-including.html)
- [TLS / ALPN](https://manual.nssurge.com/policies/tls.html)
- [WebSocket Headers](https://manual.nssurge.com/policies/vmess.html)
