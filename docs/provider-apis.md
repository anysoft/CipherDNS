# DNS Provider API 实现依据

接口核对日期：2026-10-20。实现位于 `src/provider.c`，离线测试位于 `tests/test_provider.c`。以下链接均为服务商官方文档。Provider 接口 `cdns_provider_sync()` 只接收最终 TXT 内容，不接触 AES 密钥或明文地址。

## 通用行为

每次同步先查询，再按完整域名及 TXT 类型精确匹配；不存在时创建，恰好一条时更新。内容与 TTL 都相同则不写入。多个精确匹配记录会失败，要求管理员先清理。阿里云和腾讯云要求显式配置 `zone` 与 `rr`，两者必须组成 `[common] domain`；根域记录使用 `rr = @`。不通过简单截取末尾两段猜测注册域。

所有请求固定走 HTTPS 443，使用配置的连接和读取超时；`update_timeout` 限制一次完整查询、分页与写入操作的总时间。Provider 自身不做重试；Server 统一做有限次数重试，重试时重新查询，处理写入成功但响应丢失的情况。列表最多扫描 10,000 条，分页不完整、响应解析失败、重复记录均禁止写入。服务商存在索引延迟，多个进程并发创建仍可能发生竞态；一个域名应只部署一个写入者。

当前仅管理启用状态的默认线路记录。发现阿里云禁用或非 `default` 线路记录、腾讯云禁用或非 `0` 线路记录时明确失败，避免改变已有线路语义。错误将官方机器错误码映射为固定类别：`AUTHENTICATION`、`ACCESS_DENIED`、`RATE_LIMIT`、`TEMPORARY_ERROR`、`RECORD_NOT_FOUND`、`QUOTA`、`RECORD_CONFLICT`、`INVALID_ARGUMENT`，未知错误保留 `API_REJECTED`；HTTP 4xx 业务错误也会解析分类。不输出请求头、完整签名 URL、原始 API 响应或服务商 Message。错误码依据：[阿里云 DNS 错误码](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-errorcodes)、[腾讯云 API 公共错误码](https://cloud.tencent.com/document/api/213/30435)。

## 最小权限

使用专用 RAM/CAM 子账号或作用域限定的 API Token，凭据只保存在 Server 的私有文件。程序不会调用删除记录接口。

| 服务商 | 程序实际需要的操作 | 限定范围 |
|---|---|---|
| Cloudflare | Zone 下的 DNS Edit/Write（包含读取、创建与更新；单独 Read 不足） | 仅配置的 Zone ID；不查询 Zone 列表，不要求账户管理权限 |
| 阿里云 RAM | `alidns:DescribeSubDomainRecords`、`alidns:AddDomainRecord`、`alidns:UpdateDomainRecord` | 按所链接 API 的 RAM 授权表及实际账号标识限定到目标域名资源 |
| 腾讯云 CAM | `dnspod:DescribeRecordList`、`dnspod:CreateRecord`、`dnspod:ModifyRecord` | 按 DNSPod 官方可授权资源与操作支持范围限定目标域名；不要授予 `dnspod:*` |

Cloudflare 的 DNS 编辑权限本身包含 CRUDL，因此服务商权限粒度仍允许删除；本程序不使用该能力。资源标识的账号 ID、域名 ID/名称请从云控制台及当前授权表取值，避免套用其他产品 ARN。参考：[Cloudflare Token 权限及 CRUDL 说明](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)、各阿里云 API 的 RAM 授权表（见下）、[腾讯云 CAM 策略语法](https://cloud.tencent.com/document/product/302/105718)。

## Cloudflare

使用 `api.cloudflare.com`，请求头携带 Bearer API Token。需要对指定 Zone 的 DNS 读取和编辑权限。

| 行为 | 请求 |
|---|---|
| 查询 | `GET /client/v4/zones/{zone_id}/dns_records?type=TXT&name.exact={domain}&per_page=100&page={page}` |
| 创建 | `POST /client/v4/zones/{zone_id}/dns_records` |
| 更新 | `PATCH /client/v4/zones/{zone_id}/dns_records/{record_id}` |

写入 JSON 包含 `type`、`name`、`content`、`ttl`；解析 `success`、`result`、`result_info.total_count`，不把 HTTP 200 单独视为业务成功。

依据：[查询记录](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)、[创建记录](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)、[更新记录](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/)。

## 阿里云 DNS

使用 `alidns.aliyuncs.com`，RPC API 版本 `2015-01-09`。查询调用 `DescribeSubDomainRecords`（`SubDomain`、`DomainName=zone`、`Type=TXT`、`PageNumber`、`PageSize`）；创建调用 `AddDomainRecord`；修改调用 `UpdateDomainRecord`。写入参数为 `DomainName` 或 `RecordId`，以及 `RR`、`Type`、`Value`、`TTL`、`Line=default`。读取 `DomainRecords.Record[]`、`TotalCount`、记录 ID 和业务 `Code`。显式传入 `DomainName`，避免把独立托管的子区误当成父区查询；`Status=Enable` 和 `ENABLE` 都接受，仍要求默认线路。

使用官方 RPC 签名版本 `1.0`、`HMAC-SHA1`：参数名按字典序排序，按 RFC 3986 分别编码，拼接为查询串；构造 `GET&%2F&percentEncode(query)`；以 `AccessKeySecret + &` 为 HMAC 密钥；Base64 后再次 URL 编码。每个请求生成 128 位随机 nonce 和 UTC 时间戳。HMAC-SHA1 仅用于该 API 认证，不启用 SHA1 证书签名。Mbed TLS 提供 HMAC 和 Base64。

依据：[查询](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-describesubdomainrecords)、[创建](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-adddomainrecord)、[修改](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-updatedomainrecord)、[DNS 官方 API 参考及签名例子](https://docs-aliyun.cn-hangzhou.oss.aliyun-inc.com/pdf/dns-api-reference-cn-zh-2016-07-13.pdf)、[官方 RPC 签名步骤及附加测试向量](https://www.alibabacloud.com/help/en/httpdns/latest/signature-method)。

离线测试保留 DNS 官方例子，期望签名 `uRpHwaSEt3J+6KQD//svCh/x+pI=`；另有 RPC 官方例子 `fHjifLgCEFdF3VMsNW5PCLa1Ds8=`。

## 腾讯云 DNSPod

使用中国站端点 `dnspod.tencentcloudapi.com`，API 版本 `2021-03-23`，service 为 `dnspod`，不传 Region。请求均为 `POST /`、JSON、`Content-Type: application/json; charset=utf-8`，公共头包含 `X-TC-Action`、`X-TC-Version`、`X-TC-Timestamp`。

查询调用 `DescribeRecordList`，按 `Domain`、`Offset`、`Limit=100` 分页并设置 `ErrorOnEmpty=no`，本地精确匹配 `Name` 和 `Type`。由于文档将 `TotalCount` 定义为总记录数，读取完整 Zone 而不假设筛选后的计数语义。创建使用 `CreateRecord`，更新使用 `ModifyRecord`；传入 `Domain`、`SubDomain`、`RecordType=TXT`、`RecordLine=默认`、`RecordLineId=0`、`Value`、`TTL`，更新额外传入数值 `RecordId`。读取 `Response.Error` 和 `Response.RecordId`，不能仅看 HTTP 200。

认证使用 TC3-HMAC-SHA256。规范请求签名头为 `content-type;host`，使用实际发送的 JSON 字节计算 SHA256。UTC 日期派生 Date、Service、`tc3_request` 三层 HMAC 密钥，再计算签名并放入 Authorization。系统时间必须准确。

依据：[查询记录](https://cloud.tencent.com/document/product/1427/56166)、[创建记录](https://cloud.tencent.com/document/api/1427/56180)、[修改记录](https://cloud.tencent.com/document/product/1427/56157)、[记录计数结构](https://cloud.tencent.com/document/product/1427/56185)、[TC3 签名](https://cloud.tencent.com/document/api/213/30654)、[保留完整公开示例值的官方签名文档](https://www-sg.tencentcloud.com/document/product/267/37447)。

离线 TC3 测试逐字保留官方示例 JSON 的空格及 Unicode 转义，时间戳为 `1551113065`。凭据使用明确虚拟的 `cipherdns-test-only-id` / `cipherdns-test-only-key`，避免公开样例中形似真实密钥的字符串触发 Push Protection。期望签名用 Python 标准库 `hashlib` / `hmac` 独立计算，为 `40151333c7cc410f74983d61db66beed9b99b3bb6ee6fbbd6ba40c64f545a1ab`；仍断言完整 Authorization，覆盖 UTC 日期、作用域、三级 HMAC 派生和请求规范化，无需真实云账号。

## 验证范围

测试覆盖三家服务商的查询后创建、查询后更新、相同内容不写、重复拒绝、业务错误、异常 HTTP 状态、传输失败脱敏、响应字段错误、TTL、JSON/URL 转义、线路状态及 zone/rr 校验。测试使用链接注入的 `cdns_http_request`，不连接真实云账号。真实账号的权限、套餐 TTL 限制和最终 DNS 传播需要部署环境验证。


## v0.2.0 复核与错误重试

2026-10-20 重新读取三家官方 API 文档、TTL、频率及授权表。文档核对与真实账号验收是不同项目；真实账号结果仍为 **PENDING**。

Provider 返回 `cdns_provider_result`，Server 使用 `cdns_provider_retryable()` 判断是否退避，不解析错误文本。网络传输错误、HTTP 408/5xx、服务端 `InternalError` / `ServiceUnavailable` / `FailedOperation.UnknowError` 属于可重试临时错误；429、`Throttling*`、`RequestLimitExceeded*`、`FailedOperation.FrequencyLimit` 属于限流。认证、权限、参数、配额、歧义与未知业务拒绝不进行短周期重试。所有失败保留最后成功地址。记录在查询与更新之间被删除时返回 `RECORD_NOT_FOUND`，明确要求检查配置/记录后重启；不在同一次调用内盲目创建。

Cloudflare 非 2xx 返回按 HTTP 状态分类；正常 JSON 错误识别 10000/9109 认证、81057 冲突和 81044 记录不存在。阿里云/DNSPod 同时解析 HTTP 4xx 业务错误。未知消息仅显示固定 `API_REJECTED`，不输出服务商响应正文。服务商文案或新错误码不会自动变成可重试条件。[阿里云错误码](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-errorcodes)、[DNSPod 修改记录错误表](https://cloud.tencent.com/document/api/1427/56157)。

### TXT 与 TTL

| Provider | API 中的 TXT 表示 | TTL（秒） |
|---|---|---|
| Cloudflare | `content` 是 DNS 引号字符串；写入先做 DNS 引号与反斜杠转义，再做 JSON 转义。读取拼接多个引号段，并解析反斜杠与三位十进制转义；兼容旧的无引号返回。比较使用逻辑 DNS 字节。 | `1` 为自动；普通区域 60–86400，Enterprise 可低至 30。本地接受 `1` 或 30–86400，账号套餐限制由 API 最终校验。 |
| Aliyun | `Value` 是逻辑值，仅做 URL 编码；不套用 Cloudflare 引号归一化。 | API 默认 600。官方国际站当前免费/个人套餐最低 600，企业套餐可至 1；最高 86400。应按实际账号与站点套餐选择。 |
| DNSPod | `Value` 是逻辑值，仅做 JSON 转义；不套用 Cloudflare 引号归一化。 | 1–604800；最低值依套餐而异，返回 `LimitExceeded.RecordTtlLimit` 时需调整配置。 |

Cloudflare 的 TXT 定义见[创建 API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)；TTL 见[DNS API 类型定义](https://developers.cloudflare.com/api/resources/dns/)。阿里云见[TTL 套餐表](https://www.alibabacloud.com/help/en/dns/pubz-how-to-modify-ttl-time)；DNSPod 见[CreateRecord](https://cloud.tencent.com/document/api/1427/56180)。不把 `ttl=1` 当作跨服务商通用的“自动 TTL”。降低 TTL 后，旧缓存仍可存活至原 TTL；Provider 写入确认不等于 Client 已读到新值。

### 分页与频率

Cloudflare 使用最新文档的 `name.exact` 筛选及本地完整域名复核；每页 100，读取 `result_info.total_count`。阿里云从页 1 开始、每页 100（官方上限 100）。DNSPod Offset 从 0 开始、Limit=100（官方上限 3000），读取整个区域以保持 TotalCount 语义一致。三家均最多扫描 10000 条，空页却未到总数、总数异常或多条精确 TXT 都拒绝写入。[Cloudflare 分页](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)、[阿里云分页](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describesubdomainrecords)、[DNSPod 分页与索引说明](https://cloud.tencent.com/document/product/1427/56166)。

Cloudflare 文档当前全局额度为每用户/账号 Token 1200 次/5 分钟，另有每 IP 200 次/秒限制。阿里云当前 DescribeSubDomainRecords 300 次/秒，Add/UpdateDomainRecord 各 60 次/秒；配额可因账号调整。DNSPod 查询默认 100 次/秒；添加/修改仍应遵循实际账号限额及 429/业务限流响应。CipherDNS 每个域名只应有一个写入者，以上是服务商上限，不是推荐轮询频率。[Cloudflare 限流](https://developers.cloudflare.com/fundamentals/api/reference/limits/)、[阿里云当前限额表](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-quota)、[DNSPod 查询限额](https://cloud.tencent.com/document/product/1427/56166)。

DNSPod 明确提示新建记录可能有约 30 秒索引延迟。集成测试只做读取等待，不在暂时未检索到记录时反复创建。中国站 `dnspod.tencentcloudapi.com` 与国际站 `dnspod.intl.tencentcloudapi.com` 的账号/端点不混用；本实现只支持前者。TC3 文档允许至少签名 `host` 与 `content-type`，当前签名与实际发出的 Content-Type 完全一致。[TC3 官方规范](https://cloud.tencent.com/document/api/1427/56189)。

### 权限落地

Cloudflare 在 Token 模板中选择 Zone DNS Edit/Write，并把 Zone Resources 限定为单个目标区域；直接配置其 Zone ID，不需 Zone 列表权限。单独用于 doctor 的凭据可只授 DNS Read。不要授所有区域。该服务粒度不支持本程序只写某个 TXT 名称的约束，独立测试区可进一步减小影响面。[Cloudflare Token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)。

阿里云为专用 RAM 用户只授权三条 `alidns:` Action。当前授权表中查询与创建资源为 `acs:alidns::<账号ID>:domain/<域名>`，更新表使用 `acs:alidns::<账号ID>:domain/<域名ID>`；分别按控制台真实资源填入不同 Statement，不要把三个 Action 随意套入相同的占位 ARN 或使用 `alidns:*`。只读诊断可只授 DescribeSubDomainRecords。[查询 RAM 表](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describesubdomainrecords)、[创建 RAM 表](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-adddomainrecord)、[更新 RAM 表](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-updatedomainrecord)。

腾讯云专用 CAM 子用户只授 `dnspod:DescribeRecordList`、`dnspod:CreateRecord`、`dnspod:ModifyRecord`，Resource 使用官方 DNSPod 授权表的 `qcs::dnspod::uin/<主账号UIN>:domain/<域名ID>`；不授 DeleteRecord，也不授 `dnspod:*`。只读诊断仅需查询 Action。以控制台策略校验器确认当前站点的授权支持，不复用其他产品或国际站的资源标识。[DNSPod CAM 支持表](https://intl.cloud.tencent.com/document/product/598/57108?lang=en)。

## 可选真实集成测试

见 [集成测试操作与清理策略](integration-tests.md)。`ctest --test-dir build -L integration --output-on-failure` 在未显式提供私有配置、专属测试域名及所有权确认时返回 SKIP（77）。离线 HTTP Mock 的通过不能视为真实云 API 通过。
