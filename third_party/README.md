# 固定的内置依赖

构建过程不访问网络，不查找宿主或目标设备安装的密码库。

| 依赖 | 版本 | 上游 | 许可证 |
|---|---|---|---|
| Mbed TLS | 3.6.7 LTS | https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7 | Apache-2.0 / GPL-2.0-or-later 双许可；本项目按 Apache-2.0 使用 |
| jsmn | v1.1.0 | https://github.com/zserge/jsmn/tree/v1.1.0 | MIT |
| inih | r62 | https://github.com/benhoyt/inih/tree/r62 | BSD-3-Clause |

Mbed TLS 使用官方完整发布归档（包含生成的源文件），保留 include、library、3rdparty 和许可证；原始内容未修改。裁剪选项在 `include/cipherdns/mbedtls_config.h`。采用 TLS 1.2 ECDHE-RSA/ECDHE-ECDSA + AES-GCM；保留 SHA256/SHA384 证书验证，不启用 SHA1 证书签名、TLS 服务端、DTLS、PSK、CBC、会话票据和 TLS 1.3。系统安全随机源直接作为密码库随机回调。CLIENT 只编译密码功能，不编译 TLS/X.509。

已下载文件 SHA256（Mbed TLS 已与官方 release 公布值核对；其他值用于固定本次导入内容）：

```
a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6  mbedtls-3.6.7.tar.bz2
1ed6154dedf009212a08a397e9c4ed50a0ce31d5a8301bb294e137ae3188c13b  jsmn-v1.1.0/jsmn.h
9c15fa751bb8093d042dae1b9f125eb45198c32c6704cd5481ccde460d4f8151  inih-r62.tar.gz
```

升级时重新核对官方安全公告、校验归档，运行全部测试和三个功能模式构建。不要仅替换头文件。
