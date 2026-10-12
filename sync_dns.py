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

def check_single_api(api_url):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(api_url, headers=headers, timeout=12)
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}"
        data = resp.json()
        
        if data.get("Proxyip") != "有效":
            return False, f"Proxyip={data.get('Proxyip')}"
            
        delay_str = str(data.get("延迟", ""))
        match = re.search(r"(\d+)\s*ms", delay_str)
        if not match:
            return False, f"延迟格式异常({delay_str})"
            
        delay_val = int(match.group(1))
        if delay_val >= 80:
            return False, f"延迟过高({delay_val}ms)"
        return True, f"{delay_val}ms"
    except Exception as e:
        return False, f"请求异常({str(e)[:20]})"

def verify_cf_http(ip):
    url = f"http://{ip}:443/"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        if resp.status_code == 400:
            body = resp.text.lower()
            if "the plain http request was sent to https port" in body and "cloudflare" in body:
                return True, "400校验通过"
        return False, f"返回状态码 {resp.status_code}"
    except Exception as e:
        return False, f"连接超时/拒绝"

def check_ip_worker(ip):
    api_configs = [
        ("电信24", f"https://itping.pages.dev/24={ip}:443"),
        ("联通100", f"https://itping.pages.dev/100={ip}:443"),
        ("移动184", f"https://itping.pages.dev/184={ip}:443"),
    ]
    
    logs = []
    for name, api_url in api_configs:
        ok, msg = check_single_api(api_url)
        if not ok:
            print(f"[{ip}] 淘汰 -> {name} 不合格: {msg}")
            return None
        logs.append(f"{name}:{msg}")
            
    cf_ok, cf_msg = verify_cf_http(ip)
    if not cf_ok:
        print(f"[{ip}] 淘汰 -> 443端口检测不符: {cf_msg}")
        return None
        
    print(f"[{ip}] 通过 -> {', '.join(logs)} | {cf_msg}")
    return ip

def update_cloudflare_dns(valid_ips):
    if not CF_TOKEN or not CF_ZONE_ID:
        print("错误: 缺少 CF_TOKEN 或 CF_ZONE_ID")
        return

    # 安全熔断：如果合格节点为 0，坚决不删旧解析
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
            print(f"成功解析: {ip}")
        else:
            print(f"解析失败 ({ip}): {r.text}")

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
    # 使用 5 线程排队平稳检测，避免触发测速接口频控
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(check_ip_worker, ip): ip for ip in candidate_ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_ips.append(result)

    print(f"检测完成，完全符合条件的 IP 共: {len(valid_ips)} 个")
    update_cloudflare_dns(valid_ips)
    write_status_file(valid_ips)

if __name__ == "__main__":
    main()
