#include "cipherdns/provider.h"
#include "cipherdns/http.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *host, *method, *path, *header, *body, *response;
    int status, transport_error;
} expectation;
static expectation expected[8];
static size_t expected_count, seen;
static cdns_provider_result last_result;

int cdns_http_request(const cdns_config *c, const char *host, const char *method, const char *path,
                      const char *headers, const char *body, cdns_http_response *r, char *err,
                      size_t cap) {
    expectation *e;
    assert(c->api_deadline_ms > 0);
    assert(seen < expected_count);
    e = &expected[seen++];
    assert(!strcmp(host, e->host));
    assert(!strcmp(method, e->method));
    assert(strstr(path, e->path));
    if (e->header)
        assert(strstr(headers, e->header));
    if (e->body)
        assert(body && strstr(body, e->body));
    if (e->transport_error) {
        snprintf(err, cap, "secret transport URL/token");
        return -1;
    }
    r->status = e->status ? e->status : 200;
    r->length = strlen(e->response);
    r->body = malloc(r->length + 1);
    assert(r->body);
    memcpy(r->body, e->response, r->length + 1);
    return 0;
}
void cdns_http_free(cdns_http_response *r) {
    free(r->body);
    memset(r, 0, sizeof(*r));
}

static void begin(void) {
    expected_count = seen = 0;
    memset(expected, 0, sizeof(expected));
}
static void queue(const char *host, const char *method, const char *path, const char *header,
                  const char *body, const char *response) {
    assert(expected_count < sizeof(expected) / sizeof(expected[0]));
    expected[expected_count++] = (expectation){host, method, path, header, body, response, 200, 0};
}
static void run(cdns_config *c, const char *txt, int success, const char *error) {
    char err[256] = "stale";
    last_result = cdns_provider_sync(c, txt, err, sizeof(err));
    assert((last_result == CDNS_PROVIDER_OK) == success);
    assert(seen == expected_count);
    if (success)
        assert(!*err);
    else {
        assert(strstr(err, error));
        assert(!strstr(err, "secret"));
    }
}
static cdns_config config(const char *provider) {
    cdns_config c = {0};
    snprintf(c.provider, sizeof(c.provider), "%s", provider);
    strcpy(c.domain, "_cipher.example.com");
    strcpy(c.zone, "example.com");
    strcpy(c.rr, "_cipher");
    strcpy(c.zone_id, "zone123");
    strcpy(c.token, "test-token");
    strcpy(c.access_key_id, "testid");
    strcpy(c.access_key_secret, "testsecret");
    strcpy(c.secret_id, "testid");
    strcpy(c.secret_key, "testkey");
    c.ttl = 60;
    return c;
}
#define CF "api.cloudflare.com"
#define ALI "alidns.aliyuncs.com"
#define TC "dnspod.tencentcloudapi.com"
#define CF_REC                                                                                     \
    "{\"id\":\"id123\",\"name\":\"_cipher.example.com\",\"type\":\"TXT\",\"content\":\"old\","     \
    "\"ttl\":60}"
#define ALI_REC                                                                                    \
    "{\"RecordId\":\"123\",\"DomainName\":\"example.com\",\"RR\":\"_cipher\",\"Type\":\"TXT\","    \
    "\"Value\":\"old\",\"TTL\":60,\"Status\":\"ENABLE\",\"Line\":\"default\"}"
#define TC_REC                                                                                     \
    "{\"RecordId\":123,\"Name\":\"_cipher\",\"Type\":\"TXT\",\"Value\":\"old\",\"TTL\":60,"        \
    "\"Status\":\"ENABLE\",\"LineId\":\"0\"}"
#define CF_EMPTY "{\"success\":true,\"result\":[],\"result_info\":{\"total_count\":0}}"
#define CF_ONE "{\"success\":true,\"result\":[" CF_REC "],\"result_info\":{\"total_count\":1}}"
#define CF_OK "{\"success\":true,\"result\":{\"id\":\"id123\"}}"
#define ALI_EMPTY "{\"TotalCount\":0,\"DomainRecords\":{\"Record\":[]}}"
#define ALI_ONE "{\"TotalCount\":1,\"DomainRecords\":{\"Record\":[" ALI_REC "]}}"
#define ALI_OK "{\"RecordId\":\"123\"}"
#define TC_EMPTY "{\"Response\":{\"RecordCountInfo\":{\"TotalCount\":0},\"RecordList\":[]}}"
#define TC_ONE "{\"Response\":{\"RecordCountInfo\":{\"TotalCount\":1},\"RecordList\":[" TC_REC "]}}"
#define TC_OK "{\"Response\":{\"RecordId\":123}}"

static void signatures(void) {
    char signature[1024];
    /* Alibaba Cloud DNS official 2016-07-13 API-reference example. */
    const char *ali_query =
        "AccessKeyId=testid&Action=DescribeDomainRecords&DomainName=example.com&Format=XML&"
        "SignatureMethod=HMAC-SHA1&SignatureNonce=f59ed6a9-83fc-473b-9cc6-99c95df3856e&"
        "SignatureVersion=1.0&"
        "Timestamp=2016-03-24T16%3A41%3A54Z&Version=2015-01-09";
    assert(!cdns_aliyun_sign(ali_query, "testsecret", signature, sizeof(signature)));
    assert(!strcmp(signature, "uRpHwaSEt3J+6KQD//svCh/x+pI="));
    /* Additional official RPC vector: HTTPDNS signature method. */
    assert(!cdns_aliyun_sign(
        "AccessKeyId=testid&AccountId=100000&Action=DescribeDomains&Format=XML&"
        "RegionId=cn-hangzhou&SignatureMethod=HMAC-SHA1&SignatureNonce=1d1620f8-0b3e-464c-9967-"
        "7b54a867945b&"
        "SignatureVersion=1.0&Timestamp=2016-03-29T03%3A33%3A18Z&Version=2016-02-01",
        "testsecret", signature, sizeof(signature)));
    assert(!strcmp(signature, "fHjifLgCEFdF3VMsNW5PCLa1Ds8="));
    /* Tencent Signature v3 example payload (CSS 267/37447), with deliberately
     * fictional credentials. Expected signature independently recomputed with
     * Python hashlib/hmac; literal JSON escapes and spaces affect the hash. */
    assert(!cdns_tencent_authorization(
        "cipherdns-test-only-id", "cipherdns-test-only-key",
        "cvm.tencentcloudapi.com", "cvm", 1551113065ULL,
        "{\"Limit\": 1, \"Filters\": [{\"Values\": [\"\\u672a\\u547d\\u540d\"], \"Name\": "
        "\"instance-name\"}]}",
        signature, sizeof(signature)));
    assert(!strcmp(signature,
                   "TC3-HMAC-SHA256 Credential=cipherdns-test-only-id/"
                   "2019-02-25/cvm/tc3_request, SignedHeaders=content-type;host, "
                   "Signature=40151333c7cc410f74983d61db66beed9b99b3bb6ee6fbbd6ba40c64f545a1ab"));
    assert(cdns_aliyun_sign(ali_query, "testsecret", signature, 4));
    assert(cdns_tencent_authorization("id", "key", "host", "service", 1551113065ULL, "{}",
                                      signature, 4));
}
static void cloudflare(void) {
    cdns_config c = config("cloudflare");
    begin();
    queue(CF, "GET", "type=TXT&name.exact=_cipher.example.com", "Bearer test-token", NULL,
          CF_EMPTY);
    queue(CF, "POST", "/zones/zone123/dns_records", NULL, "\"content\":\"\\\"new\\\"\"", CF_OK);
    run(&c, "new", 1, NULL);
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, CF_ONE);
    queue(CF, "PATCH", "/dns_records/id123", NULL, "\"ttl\":60", CF_OK);
    run(&c, "new", 1, NULL);
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, CF_ONE);
    run(&c, "old", 1, NULL);
    begin();
    queue(CF, "GET", "page=1", NULL, NULL,
          "{\"success\":true,\"result\":[" CF_REC "," CF_REC
          "],\"result_info\":{\"total_count\":2}}");
    run(&c, "new", 0, "AMBIGUOUS");
    begin();
    queue(CF, "GET", "page=1", NULL, NULL,
          "{\"success\":true,\"result\":[{\"id\":\"wrong\",\"name\":\"other.example.com\",\"type\":"
          "\"TXT\"}],\"result_info\":{\"total_count\":1}}");
    queue(CF, "POST", "/dns_records", NULL, "\"name\":\"_cipher.example.com\"", CF_OK);
    run(&c, "new", 1, NULL);
    begin();
    queue(CF, "GET", "page=1", NULL, NULL,
          "{\"success\":false,\"errors\":[{\"message\":\"secret\"}]}");
    run(&c, "new", 0, "API_REJECTED");
    begin();
    queue(CF, "GET", "page=1", NULL, NULL,
          "{\"success\":true,\"result\":[],\"result_info\":{\"total_count\":2}}");
    run(&c, "new", 0, "INCOMPLETE_LIST");
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, CF_EMPTY);
    queue(CF, "POST", "/dns_records", NULL, "\"content\":\"\\\"a\\\\\\\"b\\\\\\\\c\\\"\"", CF_OK);
    run(&c, "a\"b\\c", 1, NULL);
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, "{\"success\":true,\"result\":[]}");
    run(&c, "new", 0, "MALFORMED");
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, "secret");
    expected[0].status = 429;
    run(&c, "new", 0, "RATE_LIMIT (HTTP 429)");
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, "secret");
    expected[0].transport_error = 1;
    run(&c, "new", 0, "TRANSPORT_ERROR");
    strcpy(c.token, "token\r\nInjected: yes");
    begin();
    run(&c, "new", 0, "INVALID_CREDENTIAL");
}
static void aliyun(void) {
    cdns_config c = config("aliyun");
    begin();
    queue(ALI, "GET", "Action=DescribeSubDomainRecords", NULL, NULL, ALI_EMPTY);
    queue(ALI, "GET", "Action=AddDomainRecord", NULL, NULL, ALI_OK);
    run(&c, "new", 1, NULL);
    begin();
    queue(ALI, "GET", "PageNumber=1", NULL, NULL, ALI_ONE);
    queue(ALI, "GET", "Action=UpdateDomainRecord", NULL, NULL, ALI_OK);
    run(&c, "new", 1, NULL);
    begin();
    queue(ALI, "GET", "Signature=", NULL, NULL, ALI_ONE);
    run(&c, "old", 1, NULL);
    begin();
    queue(ALI, "GET", "Action=DescribeSubDomainRecords", NULL, NULL,
          "{\"TotalCount\":2,\"DomainRecords\":{\"Record\":[" ALI_REC "," ALI_REC "]}}");
    run(&c, "new", 0, "AMBIGUOUS");
    begin();
    queue(ALI, "GET", "Action=DescribeSubDomainRecords", NULL, NULL,
          "{\"Code\":\"InvalidAccessKeyId\",\"Message\":\"secret\"}");
    run(&c, "new", 0, "AUTHENTICATION");
    begin();
    queue(ALI, "GET", "Action=DescribeSubDomainRecords", NULL, NULL,
          "{\"TotalCount\":1,\"DomainRecords\":{\"Record\":[{\"RR\":\"_cipher\",\"DomainName\":"
          "\"example.com\",\"Type\":\"TXT\","
          "\"RecordId\":\"123\",\"Value\":\"old\",\"TTL\":60,\"Status\":\"DISABLE\",\"Line\":"
          "\"default\"}]}}");
    run(&c, "new", 0, "UNSUPPORTED_RECORD_STATE");
    begin();
    queue(ALI, "GET", "Action=DescribeSubDomainRecords", NULL, NULL, ALI_EMPTY);
    queue(ALI, "GET", "Value=a%22b%5Cc", NULL, NULL, ALI_OK);
    run(&c, "a\"b\\c", 1, NULL);
    begin();
    strcpy(c.zone, "wrong.com");
    run(&c, "new", 0, "INVALID_ZONE_RR");
}
static void tencent(void) {
    cdns_config c = config("dnspod");
    begin();
    queue(TC, "POST", "/", "X-TC-Action: DescribeRecordList", "\"Offset\":0", TC_EMPTY);
    queue(TC, "POST", "/", "X-TC-Action: CreateRecord", "\"RecordLineId\":\"0\"", TC_OK);
    run(&c, "new", 1, NULL);
    begin();
    queue(TC, "POST", "/", "TC3-HMAC-SHA256", NULL, TC_ONE);
    queue(TC, "POST", "/", "X-TC-Action: ModifyRecord", "\"RecordId\":123", TC_OK);
    run(&c, "new", 1, NULL);
    begin();
    queue(TC, "POST", "/", "X-TC-Version: 2021-03-23", NULL, TC_ONE);
    run(&c, "old", 1, NULL);
    begin();
    queue(TC, "POST", "/", NULL, NULL,
          "{\"Response\":{\"RecordCountInfo\":{\"TotalCount\":2},\"RecordList\":[" TC_REC "," TC_REC
          "]}}");
    run(&c, "new", 0, "AMBIGUOUS");
    begin();
    queue(TC, "POST", "/", NULL, NULL,
          "{\"Response\":{\"Error\":{\"Code\":\"AuthFailure\",\"Message\":\"secret\"}}}");
    run(&c, "new", 0, "AUTHENTICATION");
    begin();
    queue(TC, "POST", "/", NULL, NULL,
          "{\"Response\":{\"RecordCountInfo\":{\"TotalCount\":1},\"RecordList\":[{\"RecordId\":123,"
          "\"Name\":\"_cipher\","
          "\"Type\":\"TXT\",\"Value\":\"old\",\"TTL\":60,\"Status\":\"ENABLE\",\"LineId\":\"10=1\"}"
          "]}}");
    run(&c, "new", 0, "UNSUPPORTED_RECORD_STATE");
    begin();
    queue(TC, "POST", "/", NULL, NULL,
          "{\"Response\":{\"RecordCountInfo\":{\"TotalCount\":1},\"RecordList\":[]}}");
    run(&c, "new", 0, "INCOMPLETE_LIST");
    begin();
    queue(TC, "POST", "/", NULL, NULL, TC_EMPTY);
    queue(TC, "POST", "/", NULL, NULL, "{\"Response\":{\"RecordId\":\"123\"}}");
    run(&c, "new", 0, "MALFORMED");
    begin();
    strcpy(c.domain, "example.com");
    strcpy(c.rr, "@");
    queue(TC, "POST", "/", NULL, "\"Domain\":\"example.com\"", TC_EMPTY);
    queue(TC, "POST", "/", NULL, "\"SubDomain\":\"@\"", TC_OK);
    run(&c, "new", 1, NULL);
}
static void pagination(void) {
    char response[16384];
    size_t used;
    cdns_config c = config("cloudflare");
    used = (size_t)snprintf(response, sizeof(response), "{\"success\":true,\"result\":[");
    for (unsigned i = 0; i < 100; ++i)
        used += (size_t)snprintf(response + used, sizeof(response) - used,
                                 "%s{\"name\":\"other%u.example.com\",\"type\":\"TXT\"}",
                                 i ? "," : "", i);
    assert(used < sizeof(response));
    snprintf(response + used, sizeof(response) - used, "],\"result_info\":{\"total_count\":101}}");
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, response);
    queue(CF, "GET", "page=2", NULL, NULL,
          "{\"success\":true,\"result\":[" CF_REC "],\"result_info\":{\"total_count\":101}}");
    run(&c, "old", 1, NULL);
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, response);
    queue(CF, "GET", "page=2", NULL, NULL, CF_EMPTY);
    run(&c, "new", 0, "INCONSISTENT_PAGINATION");

    c = config("aliyun");
    used = (size_t)snprintf(response, sizeof(response),
                            "{\"TotalCount\":101,\"DomainRecords\":{\"Record\":[");
    for (unsigned i = 0; i < 100; ++i)
        used += (size_t)snprintf(
            response + used, sizeof(response) - used,
            "%s{\"RR\":\"other%u\",\"DomainName\":\"example.com\",\"Type\":\"TXT\"}", i ? "," : "",
            i);
    assert(used < sizeof(response));
    snprintf(response + used, sizeof(response) - used, "]}}");
    begin();
    queue(ALI, "GET", "PageNumber=1", NULL, NULL, response);
    queue(ALI, "GET", "PageNumber=2", NULL, NULL,
          "{\"TotalCount\":101,\"DomainRecords\":{\"Record\":[" ALI_REC "]}}");
    run(&c, "old", 1, NULL);
    begin();
    queue(ALI, "GET", "PageNumber=1", NULL, NULL, response);
    queue(ALI, "GET", "PageNumber=2", NULL, NULL, ALI_EMPTY);
    run(&c, "new", 0, "INCONSISTENT_PAGINATION");

    c = config("dnspod");
    used = (size_t)snprintf(
        response, sizeof(response),
        "{\"Response\":{\"RecordCountInfo\":{\"TotalCount\":101},\"RecordList\":[");
    for (unsigned i = 0; i < 100; ++i)
        used += (size_t)snprintf(response + used, sizeof(response) - used,
                                 "%s{\"Name\":\"other%u\",\"Type\":\"A\"}", i ? "," : "", i);
    assert(used < sizeof(response));
    snprintf(response + used, sizeof(response) - used, "]}}");
    begin();
    queue(TC, "POST", "/", NULL, "\"Offset\":0", response);
    queue(TC, "POST", "/", NULL, "\"Offset\":100",
          "{\"Response\":{\"RecordCountInfo\":{\"TotalCount\":101},\"RecordList\":[" TC_REC "]}}");
    run(&c, "old", 1, NULL);
    begin();
    queue(TC, "POST", "/", NULL, "\"Offset\":0", response);
    queue(TC, "POST", "/", NULL, "\"Offset\":100", TC_EMPTY);
    run(&c, "new", 0, "INCONSISTENT_PAGINATION");
}
static void error_categories(void) {
    static const struct {
        const char *code, *category;
    } cases[] = {{"Forbidden.RAM", "ACCESS_DENIED"},
                 {"UnauthorizedOperation", "ACCESS_DENIED"},
                 {"Throttling.User", "RATE_LIMIT"},
                 {"RequestLimitExceeded", "RATE_LIMIT"},
                 {"QuotaExceeded", "QUOTA"},
                 {"LimitExceeded.RecordTtlLimit", "QUOTA"},
                 {"DomainRecordDuplicate", "RECORD_CONFLICT"},
                 {"InvalidParameter.DomainRecordExist", "RECORD_CONFLICT"},
                 {"InvalidParameter.Value", "INVALID_ARGUMENT"},
                 {"Unrecognized.secret", "API_REJECTED"}};
    char response[512];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdns_config c = config("aliyun");
        snprintf(response, sizeof(response),
                 "{\"Code\":\"%s\",\"Message\":\"secret credential reflected\"}", cases[i].code);
        begin();
        queue(ALI, "GET", "DescribeSubDomainRecords", NULL, NULL, response);
        run(&c, "new", 0, cases[i].category);
        begin();
        queue(ALI, "GET", "DescribeSubDomainRecords", NULL, NULL, response);
        expected[0].status = 400;
        run(&c, "new", 0, cases[i].category);
        c = config("dnspod");
        snprintf(response, sizeof(response),
                 "{\"Response\":{\"Error\":{\"Code\":\"%s\",\"Message\":\"secret credential "
                 "reflected\"}}}",
                 cases[i].code);
        begin();
        queue(TC, "POST", "/", NULL, NULL, response);
        run(&c, "new", 0, cases[i].category);
        begin();
        queue(TC, "POST", "/", NULL, NULL, response);
        expected[0].status = 400;
        run(&c, "new", 0, cases[i].category);
    }
    {
        cdns_config c = config("cloudflare");
        begin();
        queue(CF, "GET", "page=1", NULL, NULL,
              "{\"success\":false,\"errors\":[{\"code\":10000,\"message\":\"secret token\"}]}");
        run(&c, "new", 0, "AUTHENTICATION");
        assert(last_result == CDNS_PROVIDER_AUTH);
        begin();
        queue(CF, "GET", "page=1", NULL, NULL,
              "{\"success\":false,\"errors\":[{\"code\":10000,\"message\":\"secret token\"}]}");
        expected[0].status = 400;
        run(&c, "new", 0, "AUTHENTICATION");
        assert(last_result == CDNS_PROVIDER_AUTH);
        begin();
        queue(CF, "GET", "page=1", NULL, NULL, "{}");
        expected[0].status = 403;
        run(&c, "new", 0, "ACCESS_DENIED");
    }
}
static void readonly_and_quotes(void) {
    cdns_config c = config("cloudflare");
    cdns_provider_record rec;
    char err[256];
    begin();
    queue(CF, "GET", "page=1", NULL, NULL,
          "{\"success\":true,\"result\":[{\"id\":\"id123\",\"name\":\"_cipher.example.com\","
          "\"type\":\"TXT\",\"content\":\"\\\"o\\\\108\\\" \\\"d\\\"\",\"ttl\":60}],"
          "\"result_info\":{\"total_count\":1}}");
    run(&c, "old", 1, NULL); /* quoted chunks and decimal escapes are logical DNS bytes */
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, CF_ONE);
    assert(cdns_provider_read(&c, &rec, err, sizeof(err)) == CDNS_PROVIDER_OK);
    assert(rec.exists && !strcmp(rec.value, "old") && !strcmp(rec.id, "id123") && rec.ttl == 60);
    assert(seen == expected_count && !*err);
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, CF_EMPTY);
    assert(cdns_provider_read(&c, &rec, err, sizeof(err)) == CDNS_PROVIDER_OK);
    assert(!rec.exists && !rec.id[0] && !rec.value[0] && !rec.ttl && seen == 1);
    begin();
    queue(CF, "GET", "page=1", NULL, NULL,
          "{\"success\":true,\"result\":[{\"id\":\"id123\",\"name\":\"_cipher.example.com\","
          "\"type\":\"TXT\",\"content\":\"\\\"unterminated\",\"ttl\":60}],"
          "\"result_info\":{\"total_count\":1}}");
    memset(&rec, 1, sizeof(rec));
    assert(cdns_provider_read(&c, &rec, err, sizeof(err)) == CDNS_PROVIDER_RESPONSE);
    assert(!rec.exists && !rec.id[0] && !rec.value[0] && !rec.ttl && seen == 1);
    c = config("aliyun");
    begin();
    queue(ALI, "GET", "DomainName=example.com", NULL, NULL,
          "{\"TotalCount\":1,\"DomainRecords\":{\"Record\":[{\"RecordId\":\"123\","
          "\"DomainName\":\"example.com\",\"RR\":\"_cipher\",\"Type\":\"TXT\","
          "\"Value\":\"\\\"old\\\"\",\"TTL\":60,\"Status\":\"Enable\",\"Line\":\"default\"}]}}");
    assert(cdns_provider_read(&c, &rec, err, sizeof(err)) == CDNS_PROVIDER_OK);
    assert(rec.exists && !strcmp(rec.value, "\"old\"") && seen == 1);
    c = config("dnspod");
    begin();
    queue(TC, "POST", "/", NULL, NULL, TC_ONE);
    assert(cdns_provider_read(&c, &rec, err, sizeof(err)) == CDNS_PROVIDER_OK);
    assert(rec.exists && !strcmp(rec.value, "old") && !strcmp(rec.id, "123") && seen == 1);
}
static void typed_results(void) {
    static const struct {
        int status;
        cdns_provider_result result;
        const char *category;
        int retry;
    } statuses[] = {{429, CDNS_PROVIDER_RATE_LIMIT, "RATE_LIMIT", 1},
                    {408, CDNS_PROVIDER_RETRY, "TEMPORARY_ERROR", 1},
                    {500, CDNS_PROVIDER_RETRY, "TEMPORARY_ERROR", 1},
                    {503, CDNS_PROVIDER_RETRY, "TEMPORARY_ERROR", 1},
                    {401, CDNS_PROVIDER_AUTH, "AUTHENTICATION", 0},
                    {403, CDNS_PROVIDER_DENIED, "ACCESS_DENIED", 0},
                    {404, CDNS_PROVIDER_NOT_FOUND, "RECORD_NOT_FOUND", 0},
                    {302, CDNS_PROVIDER_REJECTED, "HTTP_ERROR", 0}};
    cdns_config c = config("cloudflare");
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        begin();
        queue(CF, "GET", "page=1", NULL, NULL, "{}");
        expected[0].status = statuses[i].status;
        run(&c, "new", 0, statuses[i].category);
        assert(last_result == statuses[i].result);
        assert(cdns_provider_retryable(last_result) == statuses[i].retry);
    }
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, CF_ONE);
    queue(CF, "PATCH", "/id123", NULL, NULL,
          "{\"success\":false,\"errors\":[{\"code\":81044,\"message\":\"secret\"}]}");
    run(&c, "new", 0, "RECORD_NOT_FOUND");
    assert(last_result == CDNS_PROVIDER_NOT_FOUND && !cdns_provider_retryable(last_result));
    c = config("aliyun");
    begin();
    queue(ALI, "GET", "DescribeSubDomainRecords", NULL, NULL, ALI_ONE);
    queue(ALI, "GET", "UpdateDomainRecord", NULL, NULL,
          "{\"Code\":\"InvalidRecordId.NotFound\",\"Message\":\"secret\"}");
    run(&c, "new", 0, "RECORD_NOT_FOUND");
    assert(last_result == CDNS_PROVIDER_NOT_FOUND);
    begin();
    queue(ALI, "GET", "DescribeSubDomainRecords", NULL, NULL,
          "{\"Code\":\"InternalError\",\"Message\":\"secret\"}");
    run(&c, "new", 0, "TEMPORARY_ERROR");
    assert(last_result == CDNS_PROVIDER_RETRY && cdns_provider_retryable(last_result));
    c = config("dnspod");
    begin();
    queue(TC, "POST", "/", NULL, NULL, TC_ONE);
    queue(TC, "POST", "/", NULL, NULL,
          "{\"Response\":{\"Error\":{\"Code\":\"InvalidParameter.RecordIdInvalid\","
          "\"Message\":\"secret\"}}}");
    run(&c, "new", 0, "RECORD_NOT_FOUND");
    assert(last_result == CDNS_PROVIDER_NOT_FOUND);
    assert(!cdns_provider_retryable(CDNS_PROVIDER_OK));
    c = config("cloudflare");
    c.ttl = 2;
    begin();
    run(&c, "new", 0, "INVALID_TTL");
    assert(last_result == CDNS_PROVIDER_INVALID);
    c.ttl = 1;
    begin();
    queue(CF, "GET", "page=1", NULL, NULL, CF_EMPTY);
    queue(CF, "POST", "/dns_records", NULL, "\"ttl\":1", CF_OK);
    run(&c, "new", 1, NULL);
}
static void ownership_guards(void) {
    static const char *providers[] = {"cloudflare", "aliyun", "dnspod"};
    static const char *hosts[] = {CF, ALI, TC};
    static const char *methods[] = {"GET", "GET", "POST"};
    static const char *paths[] = {"page=1", "DescribeSubDomainRecords", "/"};
    static const char *existing[] = {CF_ONE, ALI_ONE, TC_ONE};
    static const char *empty[] = {CF_EMPTY, ALI_EMPTY, TC_EMPTY};
    char err[256];
    for (size_t i = 0; i < 3; ++i) {
        cdns_config c = config(providers[i]);
        begin();
        queue(hosts[i], methods[i], paths[i], NULL, NULL, existing[i]);
        assert(cdns_provider_sync_guarded(&c, "old", "", err, sizeof(err)) ==
               CDNS_PROVIDER_CONFLICT);
        assert(strstr(err, "OWNERSHIP_MISMATCH") && seen == 1);
        begin();
        queue(hosts[i], methods[i], paths[i], NULL, NULL, existing[i]);
        assert(cdns_provider_sync_guarded(&c, "new", "unrelated-id", err, sizeof(err)) ==
               CDNS_PROVIDER_CONFLICT);
        assert(strstr(err, "OWNERSHIP_MISMATCH") && seen == 1);
        begin();
        queue(hosts[i], methods[i], paths[i], NULL, NULL, empty[i]);
        assert(cdns_provider_sync_guarded(&c, "new", "owned-id", err, sizeof(err)) ==
               CDNS_PROVIDER_CONFLICT);
        assert(strstr(err, "OWNERSHIP_MISMATCH") && seen == 1);
        begin();
        assert(cdns_provider_sync_guarded(&c, "new", NULL, err, sizeof(err)) ==
               CDNS_PROVIDER_INVALID);
        assert(seen == 0);
    }
}
int main(void) {
    signatures();
    cloudflare();
    aliyun();
    tencent();
    pagination();
    error_categories();
    readonly_and_quotes();
    typed_results();
    ownership_guards();
    puts("provider signing vectors and HTTP mock tests passed");
    return 0;
}
