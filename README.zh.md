# UniVPN Multi Plus

基于 **[UsernameFull 的 UniVPN Multi](https://github.com/UsernameFull/univpn-multi)**。本项目是独立扩展，非 UniVPN 或联软官方产品。保留上游代码及完整原署名，详见[第三方声明](THIRD_PARTY_NOTICES.md)。

[English](README.md) · [下载发布包](https://github.com/SIPSK/univpn-multi-plus/releases) · [参与开发](CONTRIBUTING.md)

在 **Windows x64** 上，用一个本地网页和托盘管理多条原生 UniVPN 连接。当前公开版本 **0.2.5** 仅适配官方 UniVPN **10781.19.0.1214** 的已审查指定构建；版本号相同也要通过原始 EXE 的哈希校验。打包程序不需要 Docker、WSL 或另外安装 Python。

## 使用

1. 下载 **Complete Windows x64 完整包**，完整解压。
2. 首次运行 `Setup.bat`。已有匹配客户端时直接复用；需要安装或更换版本时，会打开随包附带的原样官方安装器。先断开 VPN 并退出所有原客户端，再自行操作安装界面。手动卸载旧版时，请选择**保留用户配置、保留 TAP 驱动**；工具不会自动卸载，也不会替你勾选。
3. 以后运行 `Start.bat`。账号、密码和动态口令在本地网页输入。关闭网页后，后台和连接继续运行；托盘可重新打开网页。退出管理器或运行 `Stop.bat` 前，先断开由它建立的连接。

manager-only 包不含官方安装器，需要先安装匹配客户端。源码目录不是 Complete 安装包。

首次打开会导入全部有效旧配置并保留原名称。每份配置有独立 ID，同名或同网关也不会相互覆盖。首次接管时，请自行在原客户端中断开并退出各实例；打开工具不会强制断网。之后重新打开网页，无需断开由管理器维护的连接。

点击**连接**即可。每条配置已经分配的运行资源会保留；没有可用资源时，复用上游原生流程新增实例。若当前已有管理器连接在线，网页会先确认，再暂时断开、创建一个实例，并将已保存登录信息的连接各恢复一次。取消不会改变现有连接。外部客户端、未知连接、尚未完成的验证或未保存登录信息，会先提示处理。动态口令仍需本人填写，认证失败不会自动反复重试。

配置来源与运行实例分别管理。原生旧密码只在原来的实例内复用；分配到其他实例时，网页会自然展开空登录框。勾选**保存密码**后，新凭据进入当前 Windows 用户的凭据管理器，不写入配置 JSON、日志或安装包。每条连接的**自动连接**单独设置；**开机启动**是另一个全局选项，初始关闭。自动连接每次启动只尝试一次，动态口令由本人补充。

## 数据与兼容性

程序安装到 `%LOCALAPPDATA%\UniVPNManager\App`；运行状态和私有原配置备份保存在 `%LOCALAPPDATA%\UniVPNManager`。分享发布包即可，**不要分享运行目录**。账号、密码、动态口令、启动 token、配置和密钥文件也不要发到 Issue 或截图中。

源码仓库不含官方安装器或私人 VPN 配置。Complete 发布包中的原样官方文件适用厂商自己的条款，不属于本仓库 MIT 许可范围，见[第三方声明](THIRD_PARTY_NOTICES.md)。

系统路由、DNS 和网关策略仍由 Windows 共享。原生多实例不保证任意内网网段或任意网关组合都能兼容。

| 验证内容 | 当前结果 |
| --- | --- |
| 两条真实隧道同时在线、登录和动态口令 | 已在开发机验证 |
| 创建第三个原生实例 | 已在开发机验证 |
| 三、四条隧道同时承载业务流量 | 未验证 |
| 其他官方构建、版本换装和全新机器安装 | 未验证 |
| 单元测试和本地浏览器模拟测试 | 已自动化；不创建真实服务、网卡或 VPN 连接 |

以上只描述已执行的验证，不代表对其他网关和机器的保证。

## 开发

使用 Windows x64 和 Python 3.12。测试只用临时文件和模拟接口，不要求安装 UniVPN。

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
npm install
npx playwright install chromium
npm test
```

构建不含官方安装文件的包：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe tools/build_package.py --distribution manager-only
```

如需同时构建 Complete 包，请提供含固定 EXE、CMS、CRL 的官方文件目录。构建校验哈希，不会下载或执行它们：

```powershell
.\.venv\Scripts\python.exe tools/build_package.py --distribution both --official-source 'C:\path\to\reviewed-official-files'
```

增加 `--check` 可只校验所选输入而不构建。原生维护、测试范围和浏览器选择见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可与上游

本项目自有管理器代码使用 [MIT 许可，版权 2026 SIPSK](LICENSE)。复用的 UniVPN Multi 保留其[完整 MIT 署名](vendor/LICENSE.univpn-multi)，固定于 [`0d12fbbbdad25f00c5ab656fb37f2c0e2c8e5121`](https://github.com/UsernameFull/univpn-multi/tree/0d12fbbbdad25f00c5ab656fb37f2c0e2c8e5121)。`CreateOnly` 适配有明确差异记录；原生实现和维护说明请参阅[上游项目](https://github.com/UsernameFull/univpn-multi)。
