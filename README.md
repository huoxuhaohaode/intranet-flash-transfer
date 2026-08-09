<div align="center">
  <img src="assets/icon.png" width="96" alt="内网闪传图标">

  # 内网闪传

  **把电脑里的真实文件，通过局域网安全地交付给身边设备。**

  无需账号、无需云盘、无需安装访客客户端。桌面端创建共享，访客打开加密链接或扫描二维码即可认证、预览和下载。

  [English](README_EN.md) | **简体中文**

  [![Release](https://img.shields.io/github/v/release/huoxuhaohaode/intranet-flash-transfer?style=flat-square)](https://github.com/huoxuhaohaode/intranet-flash-transfer/releases/latest)
  [![Build](https://img.shields.io/github/actions/workflow/status/huoxuhaohaode/intranet-flash-transfer/release.yml?style=flat-square&label=build)](https://github.com/huoxuhaohaode/intranet-flash-transfer/actions)
  ![Tauri](https://img.shields.io/badge/Tauri-2-24C8DB?style=flat-square&logo=tauri&logoColor=white)
  ![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-25313C?style=flat-square)

  [下载最新版](https://github.com/huoxuhaohaode/intranet-flash-transfer/releases/latest) · [查看更新记录](CHANGELOG.md) · [反馈问题](https://github.com/huoxuhaohaode/intranet-flash-transfer/issues/new/choose) · [交流讨论](https://github.com/huoxuhaohaode/intranet-flash-transfer/discussions)
</div>

<p align="center">
</p>

## 它解决什么问题？

临时把大文件、交付目录或内部资料传给同一网络里的另一台电脑，通常要经过聊天软件、云盘或 U 盘。内网闪传把这件事变成一条更直接的路径：

1. 在桌面端选择真实文件或目录。
2. 设置口令、有效期、访问模式和可选 IP 白名单。
3. 复制加密链接或二维码给访客。
4. 访客使用浏览器认证后，只读预览或下载。

文件由你的电脑直接提供，不需要先上传到第三方服务器。

## 主要特点

| 能力 | 说明 |
| --- | --- |
| 真实局域网直传 | 自动识别 IPv4 网卡并启动本机 HTTP 服务，文件不经过云端中转。 |
| 二维码与加密链接 | 每个共享生成独立访问令牌，可复制链接、全部网卡地址或保存二维码。 |
| 口令与有效期 | 口令经 `scrypt` 加盐哈希保存，可设置 1 小时、4 小时、24 小时、7 天或永不过期。 |
| 访问策略 | 支持精确 IP、CIDR 和通配段白名单；支持独占访问和一对多下载。 |
| 移动端显式开关 | 手机和平板访问默认关闭，只有共享创建者主动开启后才允许访问。 |
| 断点续传与校验 | 单文件使用 HTTP Range 续传，完成后由客户端和服务端核对 SHA-256 与文件大小。 |
| 批量 ZIP 下载 | 访客可多选文件或目录，由桌面端实时生成 ZIP 并返回校验结果。 |
| 只读访客页面 | 访客只能认证、预览和下载，不能上传、修改或删除宿主机文件。 |
| 轻量桌面端 | 基于 Tauri 2、Rust 和系统 WebView，macOS 安装包约 5 MB。 |

## 下载

前往 [GitHub Releases](https://github.com/huoxuhaohaode/intranet-flash-transfer/releases/latest)：

| 平台 | 安装包 | 当前架构 |
| --- | --- | --- |
| macOS | DMG | Apple Silicon / `aarch64` |
| Windows | NSIS EXE | 64 位 / `x64` |

> macOS 与 Windows 安装包目前使用自动化构建，未配置商业代码签名证书。系统首次运行时可能显示未知开发者或 SmartScreen 提示。

## 使用流程

### 1. 创建共享

选择访问网卡和端口，再选择本机文件或目录。设置共享名称、访问口令、有效期和访问策略。

### 2. 分享入口

控制端会生成真实局域网链接与二维码。多网卡设备还可以一次复制全部可用地址。

### 3. 访客下载

访客在同一局域网或可信 VPN 中打开链接，输入口令后查看文件列表。单文件支持断点续传，多选项目支持 ZIP 下载。

### 4. 查看结果

控制端显示租约、传输和移动端状态；访客端显示实时速度、接收字节数以及 SHA-256 校验回执。

## 安全模型

- 共享口令不会明文保存，桌面端使用 `scrypt` 加盐哈希。
- 访问链接令牌使用本机密钥和 AES-256-GCM 生成，不包含真实文件路径。
- 所有文件请求必须通过 Bearer Token 认证，并受口令有效期、客户端 IP 和访问模式约束。
- 服务端会限制认证失败频率，降低局域网内的口令爆破风险。
- 文件路径经过边界检查，访客不能跳出共享根目录。
- 移动端访问默认关闭，公开 API 不返回宿主机物理路径。

> **重要：** 当前传输通道是局域网 HTTP，不是端到端 TLS。请只在可信局域网、隔离网络或可信 VPN 中使用，不要把服务端口直接暴露到公网。

## 技术栈

- **桌面运行时：** Tauri 2
- **本地服务：** Rust、Axum、Tokio
- **界面：** React 19、TypeScript、Tailwind CSS 4
- **安全与校验：** AES-256-GCM、scrypt、SHA-256、MD5
- **打包：** macOS APFS DMG、Windows NSIS、GitHub Actions

## 本地开发

### 环境要求

- Node.js 24+
- Rust stable
- macOS 或 Windows 的 [Tauri 2 系统依赖](https://v2.tauri.app/start/prerequisites/)

```bash
git clone https://github.com/huoxuhaohaode/intranet-flash-transfer.git
cd intranet-flash-transfer
npm install
npm run tauri:dev
```

## 构建

```bash
# 类型检查
npm run lint

# macOS DMG（只能在 macOS 构建）
npm run tauri:build:mac

# Windows NSIS EXE（只能在 Windows 构建）
npm run tauri:build:win
```

推送版本标签后，GitHub Actions 会同时构建两个平台并发布 Release。

## 版本规则

每次迭代先运行：

```bash
npm run version:next
```

版本按十进制进位：`0.2.1`、`0.2.2` … `0.2.9`、`0.3.0`。脚本会同步更新 npm、Cargo 和 Tauri 配置；同一版本不会重复生成正式 DMG。

## 项目状态

项目仍处于早期阶段。登录 GitHub 后，可通过[反馈表单](https://github.com/huoxuhaohaode/intranet-flash-transfer/issues/new/choose)提交 Bug 或功能建议；一般使用问题可前往 [Discussions](https://github.com/huoxuhaohaode/intranet-flash-transfer/discussions)交流。

> GitHub 不允许匿名提交 Issue 或 Discussion，未登录访客需要先登录 GitHub 账号。

当前计划包括：

- Intel Mac 与更多 Windows 架构的正式构建
- 可选 HTTPS 传输与证书指纹确认
- 更完整的访客预览类型
- 自动更新与签名发布链路

## 致谢

README 的信息组织参考了 [LocalSend](https://github.com/localsend/localsend)、[PairDrop](https://github.com/schlagmichdoch/PairDrop) 和 [croc](https://github.com/schollz/croc) 等局域网传输项目。
