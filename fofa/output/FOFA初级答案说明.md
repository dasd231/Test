# FOFA 初级答案说明

## 1. 当前状态

- 输出文件：`答案-初级版.json`
- 题目数量：100
- 参赛包编号：`pkg-08e82c8d`
- 初级判断：95 条 FOFA Query，5 条固定不可转换答案
- 选手名称：尚未提供，暂时留空，因此当前文件不能直接提交
- 执行验证：本机没有 FOFA API 凭据，当前完成的是字段、逻辑、格式和外部事实核验，尚未对 95 条 Query 逐条执行 FOFA 搜索

本说明文件仅用于复核，不得并入比赛提交 JSON。

## 2. 作答原则

1. 优先使用 FOFA 的专用字段，不用正文近似搜索替代，例如 JS 文件使用 `js_name`、证书根域使用 `cert.domain`。
2. 先将自然语言拆成 AND、OR、NOT 条件树，再生成带显式括号的 Query。
3. 不擅自加入题目未要求的版本、端口或产品条件。
4. 非法、矛盾、主观或 FOFA 不可观测的条件，使用固定答案：`该需求不能直接转换为FOFA搜索语句`。
5. 外部事实优先依据一手资料；公开的同题草稿只用于交叉检查，不视为标准答案。

主要依据：

- [FOFA 官方 API 字段表](https://fofa.info/api)
- [FOFA 官方 Go 客户端](https://github.com/FofaInfo/GoFOFA)
- [Jenkins TCP Agent Listener Port 官方文档](https://www.jenkins.io/doc/book/security/services/)
- [Apache HTTP Server CVE-2021-41773 官方说明](https://httpd.apache.org/security/vulnerabilities_24.html)
- [GitHub Octodex](https://octodex.github.com/)

## 3. 关键答案的理由

| 题号 | 选择 | 理由 |
|---|---|---|
| M004 | `host=="www.amazon.com"` | “网站名为”要求完整匹配，使用 `host` 和精确操作符 `==`。 |
| M005 | `host="vpn"` | “域名里带有 vpn”可能出现在完整子域名中；`domain` 只表示主域，容易漏检。 |
| M013 | `(title OR body) AND country AND after` | 标题或正文只需命中一个，但国家排除和更新时间必须约束两个分支。 |
| M017 | `base_protocol="tcp"` | TCP 是传输层协议，不是 FOFA 的应用服务协议。 |
| M020 | `protocol="ftp" && base_protocol="tcp"` | 同时保证识别为 FTP，并且底层确实使用 TCP。 |
| M023 | `host*="?.?.163.com"` | 两个 `?` 分别表示两个恰好一字符的子域标签。 |
| M028 | `status_code="308" && type="subdomain"` | 状态码条件之外，题目明确要求网站类资产。 |
| M031 | `js_name="jquery.min.js"` | FOFA 有引用 JS 文件专用字段，比正文搜索更准确。 |
| M032 | `banner="200 OK"` | 题目特别说明 200 OK 是服务返回文本，因此不能写成 HTTP 状态码。 |
| M033 | `cert.is_expired=false` | “尚未过期”只描述时间状态，不等同于完整的证书有效性判断。 |
| M038 | `cert.domain="adobe.com"` | 题目明确要求证书中的根域名，专用字段比证书全文更精确。 |
| M047 | `cert.is_equal=false` | 该字段表示证书颁发者和持有者不相同。 |
| M048 | `cert.is_match=false` | 该字段表示证书与资产域名不匹配，不能与 M047 混用。 |
| M058 | 五个字段 OR | 题目明确列出访问地址、主域、CNAME 根域、证书全文和证书域名五个命中位置，必须全部保留。 |
| M063 | `(banner="IIS" && banner="1.") || header="IIS"` | Banner 分支要求同时包含两个词，而 Header 是独立的 OR 分支。 |
| M079 | `ip="40.88.0.0/16"` | 中文网络语境中的整个 B 段对应前两个八位组固定，即 `/16`。 |
| M080 | 枚举 47.96.0.1 至 47.96.0.5 | 官方字段表明确支持单 IP 和 CIDR；初级版使用五个 IP 的 OR，避免假定未确认的区间语法。 |
| M081 | 展开六个二字段组合 | 四项“至少两项非空”等价于四选二的六种 OR 组合；三项或四项非空也会命中。 |
| M082 | 域名/证书域名 OR，证书约束全局 AND | “但是证书要满足”理解为无论由主域还是证书域命中，证书匹配、有效性和到期时间都必须满足。 |
| M083 | `header="Server: nginx" && title="Welcome"` | Shodan 的 `Server: nginx` 对应 HTTP 响应头，`http.title` 对应 FOFA `title`。 |
| M089 | `app="HFS" && (80 OR (8080 AND 200))` | 状态码 200 只约束 8080 分支，不能错误约束 80 端口。 |
| M090 | 仅 Etag、Content-Length 保留值 | 题目明确要求其余响应头只检查字段名存在，并且不得限制状态码。 |
| M096 | 四个字段名 × body/banner | Jenkins 官方示例中以 Jenkins 或 Remoting 开头的字段只有 Jenkins-Agent-Protocols、Jenkins-Version、Jenkins-Session、Remoting-Minimum-Version；题目允许网页正文或服务响应原文。 |
| M097 | `icon_hash="-1493334710"` 并排除原站 | 下载 Octodex 当前 `/favicon.ico`，6518 字节，SHA-256 为 `20c67acbdf77f66d5f959a91818950c8873455151a123ea36641ccfda7a52cc3`；按 FOFA 的 Base64 + MurmurHash3 32 位有符号算法得到 `-1493334710`。 |
| M098 | `host*="*.gov.cn.*"` | 目标域名的结构性仿冒特征是把 `.gov.cn.` 嵌入一个并非 `gov.cn` 的可注册域名中；不直接把所有 `is_fraud=true` 站点都扩大进来。 |
| M099 | `app="APACHE-HTTP_Server"` | Apache 官方确认 CVE-2021-41773 对应 Apache HTTP Server；题目问“对应的产品”，因此初级版使用 FOFA 当前产品标签，不额外限制版本。 |
| M100 | 颁发者 CN + 十进制序列号 | 颁发者通用名称对应 `cert.issuer.cn`；十六进制 `63BD83716214836EF80075356161EB06` 转为十进制 `132577581667764526475870473477991557894`，避免大整数精度损失。 |

## 4. 五条不可转换答案

| 题号 | 理由 |
|---|---|
| M091 | 端口 1000000 超出合法范围 0–65535。 |
| M092 | `1.2.3.4.5` 不是合法 IP 地址或 CIDR。 |
| M093 | 同一资产的国家代码同时等于和不等于 US，条件自相矛盾。 |
| M094 | “最安全”没有明确、可观测、可排序的 FOFA 定义。 |
| M095 | 容器实时内存使用率属于运行时监控数据，不是 FOFA 的互联网资产测绘字段。 |

## 5. 初级版疑问点

以下答案先保留候选，但应在有 FOFA 账号的环境中优先执行验证：

1. **M007、M008：地域枚举**  
   `Gangwon-do`、`Bavaria`、`Munich` 可能与 FOFA 当前规范值 `Gangwon-teukbyeoljachido`、`Bayern`、`München` 不一致。

2. **M010、M011、M022、M025、M054、M066、M070、M072：平台枚举值**  
   Amazon 三类应用、`HuaWeiCloud`、海康摄像头、中间件、DigitalOcean、邮件系统、AWS 云标签、WAF/NGINX 标签均需要在 FOFA 当前规则或聚合结果中确认大小写和拼写。

3. **M023、M052、M072、M076、M098：模糊搜索边界**  
   `*=` 与 `?` 的语法已确认，但完整主机/根域是否严格锚定，以及比赛账号是否具备模糊搜索权限，需要实际执行验证。

4. **M024：独立产品版本查询**  
   `product.version="10.0.0"` 字段存在，但官方示例通常与 `product` 联用；题目明确不限制具体产品，因此暂时单独使用。

5. **M034：证书通用名称精确匹配**  
   `cert.subject.cn=="apple.com"` 符合“名称是”，但需验证该具体字段是否接受全局精确运算符 `==`。

6. **M037、M076、M081：空值/非空语义**  
   `!=""` 与 `==""` 的字段存在、字段缺失和空字符串行为，需要在比赛执行环境确认。

7. **M042：域名边界**  
   普通包含匹配可能命中 `notexample.com`；若结果偏宽，需要根据 FOFA 实测调整为证书根域字段或模糊边界表达。

8. **M082：秒级证书时间边界**  
   题目给出秒级时间，初级版完整保留；需验证 FOFA 是否按秒解析，还是只接受日期。

9. **M097：动态图标**  
   favicon 可能随网站部署变化。当前哈希可复算，但提交前最好重新抓取并再次计算。

10. **M098：仿冒特征概括**  
    当前选择域名结构特征，而没有叠加 `is_fraud=true`；后者更强调 FOFA 已标记的欺诈站点，但可能漏掉尚未打标的同类网站。

11. **M099：产品范围与漏洞版本**  
    Apache 官方说明 CVE-2021-41773 只影响 2.4.49；但题面问的是“对应的产品”，不是“所有受影响版本资产”。初级版只限定产品。如果评分意图是查找受影响资产，应增加 `product.version="2.4.49"`。

## 6. 下一轮建议

1. 提供选手名称，补齐最终 JSON 必填字段。
2. 在有 FOFA 账号的环境对上述疑问项优先执行，记录命中数和错误信息。
3. 对高置信 Query 做批量语法验证。
4. 根据验证结果形成 `答案.json` 最终版；说明文件继续保持在提交包之外。
