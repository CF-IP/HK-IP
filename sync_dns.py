import os
import re
import random
import requests
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

CF_TOKEN = os.environ.get("CF_TOKEN")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID")
SOURCE_URL = os.environ.get("SOURCE_URL", "https://jiance.rnmd.eu.org/HK")
DNS_RECORD_NAME = "yx"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

def get_candidate_ips():
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(SOURCE_URL, headers=headers, timeout=15)
        resp.raise_for_status()
        text = resp.text
    except Exception as e:
        print(f"获取源地址失败: {e}")
        return []

    ips = []
    for line in text.splitlines():
        line = line.strip()
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        if match:
            ip = match.group(1)
            if ip not in ips:
                ips.append(ip)
    return ips

def check_ip_direct(ip):
    url = f"http://{ip}:443/"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(url, headers=headers, timeout=4, allow_redirects=False)
        body = resp.text.lower()
        server = resp.headers.get("Server", "").lower()
        
        # 兼容判断 404 或 400（针对直连 443 端口的 Cloudflare 反代特征）
        if resp.status_code in [400, 404]:
            if "cloudflare" in body or "cloudflare" in server or "the plain http request" in body or "404" in body:
                print(f"[{ip}] 通过 -> HTTP {resp.status_code} (Cloudflare 特征符合)")
                return ip
        print(f"[{ip}] 淘汰 -> 返回状态码 {resp.status_code}")
    except Exception:
        print(f"[{ip}] 淘汰 -> 连接超时或拒绝")
    return None

def update_cloudflare_dns(valid_ips):
    if not CF_TOKEN or not CF_ZONE_ID:
        print("错误: 缺少环境变量 CF_TOKEN 或 CF_ZONE_ID")
        return

    if not valid_ips:
        print("【安全保护】本次检测无合格节点，保留现有 DNS 解析，不执行删除！")
        return

    headers = {
        "Authorization": f"Bearer {CF_TOKEN}",
        "Content-Type": "application/json",
    }
    list_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records?per_page=100"
    res = requests.get(list_url, headers=headers).json()
    if not res.get("success"):
        print(f"获取解析列表失败: {res.get('errors')}")
        return

    records = res.get("result", [])
    old_records = [r for r in records if r.get("name", "").startswith("yx.")]
    print(f"正在清理旧解析记录共 {len(old_records)} 条...")
    for record in old_records:
        rec_id = record["id"]
        del_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{rec_id}"
        requests.delete(del_url, headers=headers)

    print(f"正在写入新解析记录共 {len(valid_ips)} 条...")
    post_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    for ip in valid_ips:
        body = {
            "type": "A",
            "name": DNS_RECORD_NAME,
            "content": ip,
            "ttl": 60,
            "proxied": False,
        }
        r = requests.post(post_url, headers=headers, json=body)
        if r.json().get("success"):
            print(f"  + 成功解析: {ip}")
        else:
            print(f"  x 解析失败 ({ip}): {r.text}")

def write_status_file(valid_ips):
    bj_time = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    content_lines = [
        f"最后更新时间: {bj_time} (北京时间)",
        f"有效节点数量: {len(valid_ips)}",
        "",
        "IP 列表:",
    ]
    if valid_ips:
        content_lines.extend(valid_ips)
    else:
        content_lines.append("无满足条件的 IP (已触发安全熔断保留历史解析)")

    with open("最后更新信息.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(content_lines) + "\n")
    print("已成功输出: 最后更新信息.txt")

def main():
    candidate_ips = get_candidate_ips()
    print(f"从源获取到候选 IP: {len(candidate_ips)} 个")
    if not candidate_ips:
        write_status_file([])
        return

    valid_ips = []
    # 采用 20 线程并发直连，无需请求第三方 API，2 秒内即可完成筛选
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_ip_direct, ip): ip for ip in candidate_ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_ips.append(result)

    print(f"检测完成，完全符合条件的 IP 共: {len(valid_ips)} 个")
    update_cloudflare_dns(valid_ips)
    write_status_file(valid_ips)

if __name__ == "__main__":
    main()
