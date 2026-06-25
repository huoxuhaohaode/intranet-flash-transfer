# Electron 打包说明

## 关键文件

- `electron-main.cjs`：桌面主进程、本机状态持久化、真实网卡枚举、真实 HTTP 分享服务、运行期防锁屏、文件哈希和 ZIP 打包。
- `electron-preload.cjs`：渲染层安全桥接，只暴露 `window.lanTransfer` 的白名单方法。必须保持 `.cjs` 后缀，避免被 `"type": "module"` 当作 ES Module 加载。
- `assets/icon.ico`：Windows 安装包和便携版图标。
- `assets/icon.iconset`：macOS 图标源目录。
- `assets/icon.icns`：macOS DMG/App 图标，在 macOS 上由 `iconutil` 生成。

## Windows 命令

```bash
npm run lint
npm run build
npm run electron:build:win
```

Windows 产物输出到 `release/`：

- `内网闪传 Setup 0.1.0.exe`
- `内网闪传 0.1.0.exe`

## macOS 命令

必须在 macOS 主机上运行：

```bash
npm install
npm run lint
npm run mac:check
npm run electron:build:mac
```

这条命令会执行：

1. `node scripts/ensure-macos-build-host.cjs`：确认当前是 macOS。
2. `npm run build`：构建前端并生成基础图标资产。
3. `npm run mac:icon`：生成 `assets/icon.icns`。
4. `npm run mac:check:strict`：确认主进程、预加载桥、`.icns` 图标、文件清单和 DMG 配置都齐全。
5. `electron-builder --mac dmg`：生成 DMG。

## 打包前验证点

- `npm run lint` 通过。
- `node --check electron-main.cjs` 通过。
- `node --check electron-preload.cjs` 通过。
- `npm run mac:check` 通过。
- Windows 包中 `release/win-unpacked/resources/electron-preload.cjs` 存在。
- macOS 包中 `assets/icon.icns` 已生成。
- 管理端能看到真实网卡、运行期防锁屏状态和 HTTP 服务状态。
- 访客端通过 `http://真实网卡IP:端口/?token=...` 认证后能看到真实文件列表。
- 单文件下载后回执显示 SHA-256 校验通过。
- 多选打包下载生成真实 ZIP 文件。
- 独占访问和一对多下载模式都按共享策略生效。
- 移动端或请求桌面网站模式无法获得下载界面。

## 注意事项

- 管理端必须运行在 Electron 中，普通浏览器没有目录选择和本机服务控制权限。
- 局域网访问需要系统防火墙允许对应端口。macOS 首次监听端口时也可能弹出网络权限确认。
- 当前 ZIP 实现使用存储模式打包，目标是稳定和可校验，不宣称压缩率。
- 若后续要公开分发 macOS 版本，需要在 Mac 上补充 Apple Developer ID 签名和 notarization 流程。
