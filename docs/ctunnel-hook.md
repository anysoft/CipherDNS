# ctunnel Client Hook 示例

此可选集成只在本地 Hook 中修改 ctunnel Client 的 IPv6 端点。CipherDNS 核心没有 ctunnel 业务逻辑，也没有新增运行库依赖。脚本部署目标是使用 systemd 的 Linux；需要本地 Bash、jq、flock、awk、支持 `timeout -k` 的命令及带 `configtest` 的 ctunnel。原生验证和每个服务管理命令限时 5 秒，再给 1 秒强制结束宽限；示例的外层 Hook 超时为 45 秒，留出回滚时间。macOS/Windows 和非 systemd OpenWrt 需按相同事务流程另写受控服务管理适配器，不能直接运行这个示例。

1. 先按 ctunnel 的说明准备有效的 Client 配置、密钥和固定服务端公钥。对照相邻 ctunnel 仓库的 `examples/client.ini`：`server_addr` 和 `server_port` 均位于 `[common]`，验证命令为 `ctunnel configtest -c FILE`。
2. 管理员在现有 `/etc/ctunnel/client.ini` 的 `[common]` 内，将原有 `server_addr` / `server_port` 移入下面唯一的管理块。不要保留块外的同名键；其他配置仍由管理员维护。

   ```ini
   [common]
   mode = client
   # BEGIN MANAGED BLOCK: cipherdns-ctunnel-endpoint
   server_addr = 2001:db8::10
   server_port = 7000
   # END MANAGED BLOCK: cipherdns-ctunnel-endpoint
   # client_id、密钥路径、其他 common 键以及服务段保持原配置。
   ```

3. 将 [ctunnel-update.sh](../examples/hooks/ctunnel-update.sh) 安装为可信用户拥有、不可被非信任用户写入的 `/etc/cipherdns/ctunnel-update.sh`，设为 `0700`。确认脚本顶部的 ctunnel 路径、配置路径及 `ctunnel-client.service` 与本机一致。环境覆盖 `CIPHERDNS_CTUNNEL_BIN`、`CIPHERDNS_CTUNNEL_CONFIG`、`CIPHERDNS_CTUNNEL_SYSTEMCTL`、`CIPHERDNS_CTUNNEL_SERVICE` 仅供可信服务配置或本地测试使用，不可由 DNS 输入提供。
4. 按 [ctunnel-hook.ini](../examples/ctunnel-hook.ini) 配置 CipherDNS，创建私有状态和运行目录，先运行 `cipherdns doctor -c /etc/cipherdns/client.ini`。doctor 默认不会执行 Hook。单次 Client 会修改端点并重启服务，应在部署测试时显式运行。

数据流程为认证解密 → 私有 JSON 文件 → jq 检查版本、IPv6 和端口 → 比较完整配置 → ctunnel 原生验证 → 同目录原子替换 → 必要时重启 → 检查服务活跃。JSON 只作为文件数据读取；不使用 `eval`、`source` 或将地址拼成命令。同一端点重复输入不会新增备份或重启。标记缺失、重复、跨段或块外存在同名键时拒绝修改。

脚本拥有 `client.ini` 中上述唯一管理块，以及旁边的 `client.ini.cipherdns.lock` 和一次性私有备份 `client.ini.cipherdns.backup`。候选文件与事务备份位于配置目录内，保留原配置的所有者与权限。原生验证失败不替换配置；替换或服务检查失败、收到 INT/TERM 时，恢复本次调用前的文件并尝试恢复服务。一次性备份保留管理员最初配置，不会每次覆盖。SIGKILL 或断电无法运行 shell trap；可使用备份人工恢复，随后运行 configtest 和服务检查。目录必须受信任并由脚本运行用户拥有；使用足够权限的专用服务管理策略，按设备安全要求选择用户，不要赋予无关文件写权限。

ctunnel 当前没有动态端点重载接口，因此示例只在端点变化时 restart。`is-active` 只证明服务处于活跃状态；实际隧道连接及转发需另行观察 ctunnel 日志和端到端连通性。CipherDNS 将同步 Hook 创建的进程组作为受管工作，Hook 返回后会终止遗留子进程；使用 systemctl 等服务管理器启动长运行服务，不要在 Hook 中直接用 `ctunnel ... &` 留下后台进程。

验证状态：`bash -n` 为 `PASS`；本地假 ctunnel / 服务管理器的更新、重复输入、恶意字符串拒绝、验证失败、重启失败回滚、重复标记拒绝及临时文件清理回归为 `PASS`。本机未安装 ShellCheck，对应检查为 `SKIP`。真实 systemd ctunnel 服务、OpenWrt/光猫和 Windows 集成为 `PENDING`。这不是实际设备部署通过的声明。
