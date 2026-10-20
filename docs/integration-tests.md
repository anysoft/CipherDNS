# 可选真实 DNS Provider 验收

2026-10-20：Cloudflare、Aliyun、DNSPod 真实账号验收均为 **PENDING**。当前没有为本次任务提供专属账号与测试域名。离线签名向量、HTTP Mock 和无配置退出测试的 PASS 不代表真实 API 写入 PASS。

测试程序为纯 C11 的 `tests/test_integration.c`，复用正式配置、AES、TLS 和 Provider 实现，不启动外部 DNS 工具，不增加运行依赖。仅在 SERVER/BOTH 构建中编译。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=MinSizeRel
cmake --build build --parallel
ctest --test-dir build -L integration --output-on-failure
```

默认缺少显式配置时，每个测试返回 77，由 CTest 标为 SKIP。默认 CI 不配置真实云 Secrets。`ctest -LE integration` 可只运行离线回归。

## 准备独立测试区域

使用独立测试区、最小权限凭据和一次性的专用 AES Key。不要沿用生产 Server 配置。生成一个新的 32 位小写十六进制随机标识，组成 `_cipherdns-it-<32位标识>.<测试区域>`；每次测试使用新名称。程序要求该格式，且初始读取不能存在任何同名 TXT。已有记录即使包含合法 CipherDNS 密文也不会被测试接管。

创建私有目录（POSIX 权限 0700），保存 `server.ini`、凭据和 `aes.key`（均 0600、属于运行用户；Windows 使用当前用户专属 ACL）。按 [Provider 权限说明](provider-apis.md) 授权。凭据内容使用 [Server 示例](../examples/server.ini) 中 `credentials_file` 的格式，API Token/Secret 不通过命令参数或环境变量传入。

以 Cloudflare 为例，`server.ini` 使用正常 Server 配置并修改以下字段；名称中的十六进制示例必须换成自己的随机值与测试区：

```ini
[common]
mode = server
domain = _cipherdns-it-0123456789abcdef0123456789abcdef.test.example.net
key_file = /absolute/private/integration/aes.key

[server]
ip_family = both
ip_source = auto
check_interval = 30
port = 7000

[dns]
provider = cloudflare
credentials_file = /absolute/private/integration/cloudflare.ini
ttl = 60
connect_timeout = 5
read_timeout = 5
update_timeout = 15
retries = 0
```

Aliyun 使用 `provider=aliyun`、显式 `zone` 和 `rr`，普通套餐建议 `ttl=600`；DNSPod 使用 `provider=dnspod`、对应 `zone`/`rr` 和套餐允许的 TTL。`zone` 与 `rr` 必须完整组成 `common.domain`。根域 `rr=@` 不满足测试专属名称规则。不要同时运行正式 Server、其他 DDNS 工具或另一份集成测试写入同一名称。

## 显式启用一次写入验收

分别支持以下变量组，三家可以各使用独立配置文件与域名：

| Provider | 配置路径 | 专属完整域名 | 所有权/写入确认 |
|---|---|---|---|
| Cloudflare | `CIPHERDNS_INTEGRATION_CLOUDFLARE_CONFIG` | `CIPHERDNS_INTEGRATION_CLOUDFLARE_DOMAIN` | `CIPHERDNS_INTEGRATION_CLOUDFLARE_CONFIRM` |
| Aliyun | `CIPHERDNS_INTEGRATION_ALIYUN_CONFIG` | `CIPHERDNS_INTEGRATION_ALIYUN_DOMAIN` | `CIPHERDNS_INTEGRATION_ALIYUN_CONFIRM` |
| DNSPod | `CIPHERDNS_INTEGRATION_DNSPOD_CONFIG` | `CIPHERDNS_INTEGRATION_DNSPOD_DOMAIN` | `CIPHERDNS_INTEGRATION_DNSPOD_CONFIRM` |

也支持一次只运行一个 Provider 时的通用 `CIPHERDNS_INTEGRATION_CONFIG`、`CIPHERDNS_INTEGRATION_DOMAIN`、`CIPHERDNS_INTEGRATION_CONFIRM`；专用变量优先。CONFIRM 必须与 DOMAIN 完全一致，表示操作者确认拥有并授权修改这个专属测试名称。配置中的 Provider/域名也必须一致。不要将真实凭据填写在这些变量内。

```sh
export CIPHERDNS_INTEGRATION_CLOUDFLARE_CONFIG=/absolute/private/integration/server.ini
export CIPHERDNS_INTEGRATION_CLOUDFLARE_DOMAIN=_cipherdns-it-0123456789abcdef0123456789abcdef.test.example.net
# 设置此变量即确认该名称专用于本次测试，并授权创建和更新 TXT。
export CIPHERDNS_INTEGRATION_CLOUDFLARE_CONFIRM="$CIPHERDNS_INTEGRATION_CLOUDFLARE_DOMAIN"
ctest --test-dir build -L integration -R cloudflare --output-on-failure
unset CIPHERDNS_INTEGRATION_CLOUDFLARE_CONFIG CIPHERDNS_INTEGRATION_CLOUDFLARE_DOMAIN CIPHERDNS_INTEGRATION_CLOUDFLARE_CONFIRM
```

程序先完整、只读发现并拒绝已有 TXT，然后通过 create-only guard 再次发现后创建。后续 update-only guard 要求仍是同一个记录 ID，缺失或出现其他 ID 时拒绝修改。多个精确 TXT、非默认线路、禁用记录同样拒绝。云 API 不提供跨列表与写入的通用原子锁；必须保持此名称独占，一个测试进程使用一个新名称。

## 测试流程及结果边界

1. 检查配置、凭据和 Key 的私有权限；校验测试域名与确认值。
2. 只读查询确认名称不存在。
3. 使用现有 CD1 AES-GCM 协议，加密文档示例地址 `192.0.2.1` / `2001:db8::1`，创建 TXT。
4. 只读 Provider API 验证逻辑值、TTL、记录 ID及认证解密结果。
5. 加密 `192.0.2.2` / `2001:db8::2`，更新同一记录 ID，再次只读验证。
6. 重复提交同一份密文并验证结果。离线 Mock 单独断言这一步没有调用写入 API；真实测试只能验证结果稳定，不能以相同值证明服务商未收到写请求。

每次验证最多等待 60 秒，只进行读取。DNSPod 新建记录存在约 30 秒索引延迟；读取暂时未出现时不会重新创建。写操作无自动重试，避免响应丢失后的重复创建；若失败，控制台可能已经有记录，应按下节检查。日志只输出阶段、固定错误类别、测试名称与记录 ID，不输出 API 密钥、签名 URL、AES Key、密文或原始响应。

以上只证明 Provider API 的创建、更新、重复同步及读取一致性。系统递归 DNS、公共/权威 DNS 传播与 Client 查询链路仍需独立验收；等待原 TTL/负缓存过期后，使用配置到同一 Key 的 Client doctor 检查 TXT 与解密。测试不执行 Hook。不能把 API 写入成功记录为客户端已读取成功。

## 归属、保留与清理

测试使用 `_cipherdns-it-<唯一标识>` 明确标记归属，并在开始时拒绝已有 TXT。创建后不执行任何自动删除。成功或失败后都会提示专属名称和已知记录 ID；若写入响应丢失，ID可能未知，此时从控制台按完整名称查找。

由操作者核对本轮配置、测试日志中的名称与记录 ID、控制台创建时间及实际值，只手工删除确认属于本轮的 TXT。不要批量删除整个测试区或其他同名 TXT。未完成清理也可保留记录做后续只读 DNS/Client 检查；下次写入验收换新名称。日志、配置与凭据文件不提交到仓库。

验收报告逐 Provider 填写实际站点、账号权限范围、TTL、阶段结果与时间。未运行填写 PENDING；因环境缺失跳过写入填写 SKIP；执行后失败填写 FAIL 并保存脱敏阶段日志。只有真实执行全部 API 步骤才填写该 Provider 的真实 API PASS；递归/权威传播需单列结果。
