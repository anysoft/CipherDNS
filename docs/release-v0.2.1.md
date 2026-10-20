# CipherDNS v0.2.1

v0.2.1 修复 Release 内部校验对 Windows CRLF 换行的兼容性。AES `CD1:` 协议、DNS Provider、缓存和 Hook 的业务逻辑保持 v0.2.0 行为。

## 修复

- 将 Release 内联 Python 提取为 `scripts/verify-release.py`，UTF-8 解码后统一 CRLF/LF，再按完整字段检查 `verification: PASS` 和二进制 SHA256。
- 保留可执行文件与报告的必需检查，拒绝损坏归档、重复成员、非普通文件和错误包目录。任何失败均输出包名及原因并阻止发布。
- 新增 24 项自动化测试，覆盖 LF、CRLF、15 包组合、哈希不匹配、FAIL、缺文件和损坏 ZIP/TAR；纳入 CI。
- Release 按 Tag 版本选择对应发布说明；默认构建及打包版本同步到 0.2.1。

## 验证与发布

已实际下载 v0.2.0 失败运行的全部 11 个 Artifact：来源摘要与 GitHub 官方记录一致，内部 15 个发布包的外部 SHA256 全部通过。旧校验仅 Windows BOTH/CLIENT 两包失败；修复后的脚本 15/15 通过。24 项自动化测试和 Actionlint 通过。本机 macOS ARM64 的 v0.2.1 构建、8 项离线 CTest、包内版本和发布说明检查通过；三家真实云集成测试因未配置凭据 SKIP。

v0.2.1 Tag 触发完整构建矩阵，所有必需构建、测试、15 个包及校验报告成功后才发布。已有 v0.2.0 Tag 保持不变。跨平台实机、真实云写入和长期 soak 等未完成项仍以既有验证文档为准，不将打包修复视为新增业务验收。
