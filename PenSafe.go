package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

var allVuln = make(map[string][]string)

// HTTP 客户端配置
var client = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

const (
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	purple  = "\033[35m"
	reset   = "\033[0m"
)

// 敏感路径列表
var sensitivePaths = []string{"/admin", "/config", "/backup", "/test", "/private", "/.git", "/.env"}

func main() {
	helpFlag := flag.Bool("h", false, "显示帮助信息")
	urlsFlag := flag.String("u", "", "要扫描的URL列表，空格分隔")
	fileFlag := flag.String("t", "", "包含URL列表的txt文件路径，每行一个URL")
	flag.Parse()

	// 显示帮助信息
	if *helpFlag {
		flag.Usage()
		return
	}

	// 获取扫描的URL列表
	urls, err := getURLs(*urlsFlag, *fileFlag)
	if err != nil {
		fmt.Println(red + "[!] 错误: " + err.Error() + reset)
		return
	}

	// 扫描每个URL
	for _, url := range urls {
		scanURL(url)
	}

	fmt.Println(green + "扫描完毕" + reset)
}

// 获取URL列表，支持直接传入和文件读取
func getURLs(urlsFlag, fileFlag string) ([]string, error) {
	if urlsFlag != "" {
		return strings.Fields(urlsFlag), nil
	} else if fileFlag != "" {
		return readLinesFromFile(fileFlag)
	}
	return nil, fmt.Errorf("请使用 -u 传递URL或 -t 传递包含URL的文件路径")
}

// 扫描单个URL
func scanURL(url string) {
	// 确保URL格式正确
	fmt.Printf(green+"\n开始扫描 --> %s\n"+reset, url)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	// 获取响应头
	headers, err := getHeaders(url)
	if err != nil {
		fmt.Printf(red+"[!] 获取Headers失败: %v\n"+reset, err)
		return
	}

	// 显示响应头
	displayHeaders(headers)

	// 获取并记录漏洞信息
	allVuln[url] = appendVuln(allVuln[url], getHeadersVuln(headers)...)
	allVuln[url] = appendVuln(allVuln[url], getOptionsVuln(url)...)
	allVuln[url] = appendVuln(allVuln[url], checkRobotsTxt(url)...)
	allVuln[url] = appendVuln(allVuln[url], checkInfoLeakage(headers)...)

	fmt.Println(strings.Repeat("_", 60))
}

// 显示响应头信息
func displayHeaders(headers map[string]string) {
	for key, value := range headers {
		fmt.Printf("\t   %s : %s\n", key, value)
	}
	fmt.Println(strings.Repeat("- ", 20))
}

// 获取HTTP头信息
func getHeaders(url string) (map[string]string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	// 根据状态码打印不同颜色
	statusColor := getStatusColor(resp.StatusCode)
	fmt.Printf(statusColor+"[*] GET method Headers Response: %d\n"+reset, resp.StatusCode)
	return headers, nil
}

// 根据HTTP状态码返回颜色
func getStatusColor(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return green
	case statusCode >= 300 && statusCode < 400:
		return yellow
	case statusCode >= 400 && statusCode < 500:
		return red
	case statusCode >= 500 && statusCode < 600:
		return purple
	default:
		return reset
	}
}

// 合并漏洞信息
func appendVuln(vulnList []string, vulns ...string) []string {
	return append(vulnList, vulns...)
}

// 获取HTTP头部漏洞
func getHeadersVuln(headers map[string]string) []string {
	vulnHeaders := map[string]string{
		"X-Frame-Options":        ".*",
		"Content-Security-Policy": ".*",
		"Set-Cookie":             ".*",
		"X-XSS-Protection":       ".*",
		"X-Content-Type-Options": ".*",
	}

	var result []string
	for key := range vulnHeaders {
		if value, exists := headers[key]; exists {
			result = append(result, checkVulnHeaders(key, value)...)
		} else {
			result = append(result, fmt.Sprintf("(响应头缺失类) %s 头缺失", key))
			fmt.Printf(red+"[+] (响应头缺失类)\tFind vuln: %s 头缺失\n"+reset, key)
		}
	}
	return result
}

// 检查HTTP头部是否有漏洞
func checkVulnHeaders(key, value string) []string {
	var result []string
	switch key {
	case "Set-Cookie":
		if !strings.Contains(strings.ToLower(value), "httponly") {
			result = append(result, "(响应头缺失类) Set-Cookie 缺少 HttpOnly")
			fmt.Println(red + "[+] (响应头缺失类)\tFind vuln: HttpOnly 缺失" + reset)
		}
		if !strings.Contains(strings.ToLower(value), "secure") {
			result = append(result, "(响应头缺失类) Set-Cookie 缺少 Secure")
			fmt.Println(red + "[+] (响应头缺失类)\tFind vuln: Secure 缺失" + reset)
		}
	case "X-XSS-Protection":
		if !strings.Contains(value, "1") {
			result = append(result, "(响应头缺失类) X-XSS-Protection 缺失或无效")
			fmt.Println(red + "[+] (响应头缺失类)\tFind vuln: X-XSS-Protection 缺失或无效" + reset)
		}
	case "X-Content-Type-Options":
		if value != "nosniff" {
			result = append(result, "(响应头缺失类) X-Content-Type-Options 缺失或无效")
			fmt.Println(red + "[+] (响应头缺失类)\tFind vuln: X-Content-Type-Options 缺失或无效" + reset)
		}
	}
	return result
}

// 获取OPTIONS方法支持的漏洞
func getOptionsVuln(url string) []string {
	var result []string
	req, _ := http.NewRequest("OPTIONS", url, nil)
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		if allow := resp.Header.Get("Allow"); allow != "" {
			fmt.Printf(green+"[*] 支持方法: %s\n"+reset, allow)
		}
	}
	return result
}

// 检查robots.txt中的敏感路径
func checkRobotsTxt(url string) []string {
	var result []string
	robotsUrl := url + "/robots.txt"
	resp, err := http.Get(robotsUrl)
	if err != nil {
		fmt.Printf(red+"[+] (robots.txt) 获取失败: %v\n"+reset, err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf(green+"[*] Found robots.txt: %s\n"+reset, robotsUrl)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.ToLower(scanner.Text())
			for _, path := range sensitivePaths {
				if strings.Contains(line, path) {
					result = append(result, fmt.Sprintf("(robots.txt) 敏感路径发现: %s", path))
					fmt.Printf(red+"[+] (robots.txt) 敏感路径发现: %s\n"+reset, path)
				}
			}
		}
	}
	return result
}

// 检查信息泄露
func checkInfoLeakage(headers map[string]string) []string {
	var result []string
	if value, exists := headers["X-Powered-By"]; exists {
		result = append(result, fmt.Sprintf("(信息泄露) X-Powered-By: %s", value))
		fmt.Printf(red+"[+] (信息泄露) X-Powered-By: %s\n"+reset, value)
	}

	if value, exists := headers["Server"]; exists {
		result = append(result, fmt.Sprintf("(信息泄露) Server: %s", value))
		fmt.Printf(red+"[+] (信息泄露) Server: %s\n"+reset, value)
	}

	return result
}

// 从文件读取URL列表
func readLinesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}
