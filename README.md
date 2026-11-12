# Surge VLESS 订阅导入 · iOS 优先

**免服务器，在 Surge iOS 内转换 VLESS 订阅。** 手机填入一次原始订阅地址，由本机脚本生成 Surge 节点列表；策略组引用一次，之后由 Surge 定期请求更新。

> **0.2.0 Beta：转换逻辑、存储、HTTP 适配器与打包脚本有自动测试；尚未完成 Surge iOS 真机验收。** 特别需要确认该版本 Surge 自身拉取 `policy-path` 时能触发本机请求脚本。没有真机证据前，不宣称完整自动更新链路已验证。

不需要 Python、Mac、Docker 或第三方转换站。模块不替换整份配置、不自动修改规则和现有策略组。

## iPhone 安装

要求 **Surge iOS 6.0.0+**，开启 Surge 接管网络和脚本功能。本模块使用 WebView 引擎。

1. 在 Surge 的「模块」中安装以下链接并启用：

   ```text
   https://raw.githubusercontent.com/StevenLi-codex/surge-vless-importer/main/module/surge-vless.sgmodule
   ```

   [查看模块](module/surge-vless.sgmodule) · [查看完整脚本](module/surge-vless.js)

2. 保持 Surge 开启，在 Safari 地址栏完整输入 **`http://surge-vless.invalid/`**。注意是 `http`，不是 `https`。这是本机拦截的虚拟地址，`.invalid` 不是本项目注册的公网域名。不需要安装或信任 MITM 证书；若无法打开，不要把真实订阅拼到地址栏，先看下方排查。
3. 粘贴 **HTTPS 原始订阅链接**，点「导入」。兼容 Clash/Mihomo YAML、JSON、VLESS 链接及 Base64 链接订阅。也可以直接粘贴节点内容，但静态内容不会自动跟随上游更新。
4. 复制页面生成的策略组行，添加到**现有配置的 `[Proxy Group]` 段内**，再把 `VLESS订阅` 加入你原来的选择组。只需设置一次，不要再新建重复段标题。

   ```ini
   # 在已有的 [Proxy Group] 内加入页面生成的完整行：
   VLESS订阅 = select, policy-path=http://surge-vless.invalid/list/<本机随机令牌>.list, update-interval=3600

   # 在你原有的选择组中追加 VLESS订阅；保留原来的其他成员。
   # 示例：原选择组 = select, 原成员1, 原成员2, VLESS订阅
   ```

   **不要直接复制占位示例。** 页面生成的链接带本机随机令牌；在管理页替换订阅时链接保持不变。清除数据后重新导入会生成新链接，需要更新策略组引用。

## 更新与失败保护

- Surge 按 `update-interval=3600` 请求节点列表；脚本在缓存超过一小时后下载上游并本机转换。不是 iOS 永久在线后台任务，实际刷新时机受 Surge、系统和网络状态影响。
- 点击管理页「立即更新」可主动获取新数据。节点列表链接只在启用该模块的本机有效，**不是可以分享给其他设备的公网订阅**。
- 下载、转换、保存失败不替换上次有效数据。自动刷新失败时返回旧列表并发出本机提醒，不悄悄清空节点。
- 新订阅导入成功后会替换旧节点，不累积重复节点。当前版本管理一个订阅入口；如需多个来源，可用上游已聚合订阅。

## 隐私与安全边界

- 原始订阅地址、节点凭据与缓存保存在 **Surge `$persistentStore`**，用于后续更新；不是加密保险箱，Surge 的本机存储、备份或诊断导出可能包含这些数据。网页不使用 localStorage、Cookie、外部资源或遥测，不回填已保存的订阅地址。
- 请求只发送到用户填入的 HTTPS 订阅服务器及其经过检查的 HTTPS 跳转目标。关闭自动 Cookie 和自动跳转，至多手动跟随三次跳转，不关闭证书验证。第三方 CDN 可能是上游指定的下载目标，不是转换站。
- 不接受明文 HTTP 订阅、带用户名密码的 URL、明显的本地/内网 IP 或内部域名、IPv6 字面量和 URL 片段。此检查不等于 DNS 重绑定防护，不能把本机脚本视为隔离沙箱；只导入你信任的上游。
- 本机管理 API 只接受自定义请求头、同源请求，不开放跨域 CORS。列表使用随机令牌。模块将虚拟域名固定到 `127.0.0.1`，并添加精确 REJECT 规则作为脚本未处理时的后备；它不对外开放端口。
- `max-size` 只约束进入请求脚本的请求体，不是 `$httpClient` 下载流量限额。下载后才检查 2 MiB 大小；恶意大响应仍可能先消耗内存。请勿导入不可信超大订阅。
- GitHub 仅分发公开模块和脚本，不接收订阅数据；脚本链接随 `main` 更新，意味着你信任本仓库的后续代码。需要固定版本时可将两处链接改为同一个经过审核的提交 SHA。
- 删除模块不一定清除 Surge 脚本存储。停用前可用管理页「清除本机数据」删除本项目保存的订阅和缓存；已经由 Surge 导入的节点缓存仍需在 Surge 自行清理。

## 不兼容与限制

仅输出 VLESS。支持 TCP/RAW、TLS、REALITY、XTLS Vision、WebSocket 和 gRPC 的 Surge 官方组合。XHTTP、HTTPUpgrade、mKCP、VLESS Encryption 等不兼容项跳过并报告；没有有效节点则保留旧数据。

`client-fingerprint` / `fp` / `spx` 不输出，Surge 使用自己的 TLS 栈。ML-KEM 等没有对应设置时会提示；**格式转换成功不代表节点握手或连接已验证**。不修补第三方 Surge 修改版，不绕过客户端授权或协议能力限制。

## 管理页打不开 / 节点不更新

1. 确认使用完整的 `http://surge-vless.invalid/`，Surge 及模块开启，脚本已从 GitHub 下载成功。Safari 的 HTTPS 自动升级、当前配置的跳过代理列表、其他先匹配的脚本可能使本地拦截失效。
2. 在 Surge 请求记录和脚本日志检查这一个虚拟域名；不要公开含令牌的下载 URL、节点内容或诊断文件。
3. 管理页正常不等于 Surge 自身 `policy-path` 下载经过同一引擎。先在 Safari 打开生成的列表链接，再在 Surge 手动刷新该外部策略组。若前者有节点后者失败，需根据真机日志调整接入方式，不能声称已支持自动更新。
4. 当前为 Beta，欢迎提交脱敏后的系统版本、Surge 版本、错误类型；不要提交真实订阅或凭据。

## 开发与验证

```sh
npm ci --ignore-scripts
npm run build
npm test
npm audit --omit=dev

# 保留的 Python 工具测试
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

`module/surge-vless.js` 是自包含产物，打包 YAML 解析器，不在手机动态加载 npm/CDN 依赖。源码在 `ios/`，第三方许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。Node 测试使用 Surge API 适配模拟环境，不冒充 Surge iOS 真机测试。

---

## 备用：Mac / Python 手动导出

以下是原有离线导出工具，与上面的 iOS 模块是两条独立路径。**Python 工具不保存订阅链接**，运行时读取后导出 `.list`；它不会自动更新手机节点。

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

- [HTTP 请求脚本与本地响应](https://manual.nssurge.com/scripting/http-request.html)
- [Surge JavaScript API](https://manual.nssurge.com/scripting/api.html)
- [Surge 模块限制](https://manual.nssurge.com/profile/module.html)
- [VLESS 参数与支持组合](https://manual.nssurge.com/policies/vless.html)
- [外部策略列表 policy-path](https://manual.nssurge.com/policy-groups/policy-including.html)
- [TLS / ALPN](https://manual.nssurge.com/policies/tls.html)
- [WebSocket Headers](https://manual.nssurge.com/policies/vmess.html)
