# -*- coding: utf-8 -*-
"""代理池维护脚本（修复版）

修复要点：
1. ips.txt 只进不出 -> 现在每次都会复检，失效代理直接剔除
2. 候选池 verify.txt 与 ips.txt 合并复检，避免枯竭
3. 保存失败静默吞掉 -> 增加日志
"""

import os
import re
import time
import random
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from logger import logger

BASE_URL = os.environ.get("MT_BASE_URL", "https://bbs.binmt.cc").rstrip("/")
PROBE_URL = f"{BASE_URL}/forum.php?mod=guide&view=hot"
TIMEOUT = int(os.environ.get("MT_TIMEOUT", "12"))
MAX_CANDIDATE = int(os.environ.get("MT_MAX_CANDIDATE", "600"))

HEADERS = {
    'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'keep-alive',
}

IP_RE = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\s]\s*(\d{2,5})\s*$')

VERIFY_FILE = "src/verify.txt"
IPS_FILE = "src/ips.txt"


def validate_ip_port(ip, port):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_multicast or ip_obj.is_unspecified or not ip_obj.is_global:
            return False
    except ValueError:
        return False
    try:
        return 1 <= int(port) <= 65535
    except ValueError:
        return False


def read_list(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = IP_RE.match(line)
                if m and validate_ip_port(m.group(1), m.group(2)):
                    out.append(f"{m.group(1)}:{m.group(2)}")
    except Exception:
        pass
    return out


def verify(proxy):
    proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
    start = time.time()
    try:
        r = requests.get(PROBE_URL, headers=HEADERS, proxies=proxies, timeout=TIMEOUT)
        return proxy, (r.ok and r.status_code == 200), int((time.time() - start) * 1000)
    except Exception:
        return proxy, False, -1


def save(ips, pending):
    try:
        os.makedirs("src", exist_ok=True)
        with open(IPS_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(ips)))
        with open(VERIFY_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(pending)))
    except Exception as e:
        logger.error(f"写入代理文件失败: {e}")
        return
    try:
        os.system('git config --local user.name "github-actions[bot]" >/dev/null 2>&1')
        os.system('git config --local user.email "github-actions[bot]@users.noreply.github.com" >/dev/null 2>&1')
        if os.system(f'git add {IPS_FILE} {VERIFY_FILE} >/dev/null 2>&1') == 0:
            os.system('git commit -m "更新代理池" >/dev/null 2>&1')
            os.system('git pull --quiet --rebase >/dev/null 2>&1')
            os.system('git push --quiet --force-with-lease >/dev/null 2>&1')
            logger.info("代理池已更新")
    except Exception as e:
        logger.error(f"提交代理池失败: {e}")


def main():
    old_ips = set(read_list(IPS_FILE))
    candidates = set(read_list(VERIFY_FILE))

    # 老代理也要复检，失效的剔除
    candidates -= old_ips
    pool = list(old_ips) + list(candidates)
    random.shuffle(pool)
    pool = pool[:MAX_CANDIDATE]

    logger.info(f"待验证代理 {len(pool)} 个（其中复检老代理 {len(old_ips)} 个）")

    good, dead = [], []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futures = [ex.submit(verify, p) for p in pool]
        for fu in as_completed(futures):
            proxy, ok, ms = fu.result()
            (good if ok else dead).append((proxy, ms))

    good.sort(key=lambda x: x[1])
    logger.info(f"可用 {len(good)} / 失效 {len(dead)}")
    for i, (proxy, ms) in enumerate(good[:20], 1):
        logger.info(f"  {i}: {proxy} - {ms}ms")

    ips = {p for p, _ in good}
    # 未验证通过的候选重新放回候选池（限量，避免无限膨胀）
    pending = set(candidates) - ips
    save(ips, list(pending)[:400])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"运行异常: {type(e).__name__} {e}")
