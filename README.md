# PenSafe（水洞扫描工具）

## 简介

**渗透测试安全（Penetration Testing + Safe）**：在渗透测试和网络安全领域，“Pen”可能代表“Penetration”（渗透测试），而“Safe”表示安全的意思。PenSafe（渗透测试安全扫描器），能用上此工具说明测试系统很安全！！！

## 特性

- 检测常见的HTTP响应头漏洞（如 `Set-Cookie`、`X-XSS-Protection` 等）。
- 检查 `robots.txt` 文件中是否包含敏感路径。
- 信息泄露检测（如 `X-Powered-By`、`Server` 头部）。
- 支持多种方式获取要扫描的URL：直接传入URL，或从文件中读取URL。
- 根据HTTP状态码输出不同的颜色标识，便于快速识别问题。

## 安装与使用

### 1. 编译项目

确保你已经安装了Go环境，使用以下命令编译代码：

```
go build -o PenSafe.exe main.go
```

### 2. 使用命令行工具
![image](https://github.com/user-attachments/assets/512ab4e3-eb7b-4676-8858-d7d9dd6624d3)
#### 查看帮助信息

```
PenSafe.exe -h
```

#### 扫描单个URL

```
PenSafe.exe -u http://example.com
```

#### 从文件中读取URL并扫描

文件格式：每行一个URL，例如 `urls.txt`：

```
http://example.com
https://another-site.com
```

扫描命令：

```
PenSafe.exe -t urls.txt
```

### 3. 扫描过程说明

工具会扫描每个URL，执行以下操作：

- 获取并显示HTTP响应头。
- 检查HTTP响应头中是否存在常见的安全漏洞（如 `Set-Cookie`、`X-XSS-Protection` 等）。
- 检查`robots.txt`文件中是否包含敏感路径（如 `/admin`、`/config` 等）。
- 检查是否泄露信息（如 `X-Powered-By`、`Server` 头部）。

### 4. 输出说明

- 绿色：表示无问题或成功检测。
- 红色：表示发现漏洞或问题。
- 黄色：表示可能的警告或重定向。
- 紫色：表示服务器错误。

例如：

```
[*] GET method Headers Response: 200
    X-Frame-Options : SAMEORIGIN
    Content-Security-Policy : default-src 'self'
    Set-Cookie : sessionid=abcd1234; Secure; HttpOnly
    X-XSS-Protection : 1; mode=block
    X-Content-Type-Options : nosniff
------------------------------------------------------------
```

如果在`robots.txt`文件中找到敏感路径，则会显示类似：

```
[+] (robots.txt) 敏感路径发现: /admin
```

### 5. 错误处理

如果工具无法访问URL，或者获取响应头失败，将会输出类似：

```
[!] 获取Headers失败: 连接超时
```

## 依赖

- Go 1.18+ 版本。
- 网络访问权限。

## 注意事项

- 扫描工具执行时可能对目标网站造成一定的负担，请确保你有合法权限进行扫描。
- 该工具适用于渗透测试、漏洞扫描等目的，但不用于恶意攻击。

## 参考链接：

https://github.com/linshaoSec/WaterExp
