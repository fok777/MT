# -*- coding: utf-8 -*-
"""MT 论坛自动签到（修复版）

修复要点：
1. 代理全部失效时会静默跳过 -> 现在有直连兜底，保证签到一定被尝试
2. 签到/登录的成功判定过窄 -> 改为多模式匹配
3. formhash / loginhash 提取正则过脆 -> 改为多模式 + 非空校验
4. 签到失败却 exit 0，Actions 永远绿色 -> 失败时 exit 1
5. 代理池无补充来源 -> 可选在线抓取免费代理
6. 论坛前置阿里云 ESA acw_sc__v2 JS 挑战 -> 首次访问自动计算 cookie 过挑战（核心修复）
"""

import os
import re
import sys
import time
import random
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

import esa
from preferences import prefs
from logger import logger

# ------------------------- 配置 -------------------------
BASE_URL = os.environ.get("MT_BASE_URL", "https://bbs.binmt.cc").rstrip("/")
TIMEOUT = int(os.environ.get("MT_TIMEOUT", "20"))
MAX_PROXY = int(os.environ.get("MT_MAX_PROXY", "250"))
# proxy = 国内代理优先，失败再直连（默认）
#         GitHub runner 位于海外，直连易触发论坛滑块验证，故默认不走直连
# auto  = 代理优先，代理全部失效时才用直连兜底
# direct= 只用直连
PROXY_MODE = os.environ.get("MT_PROXY_MODE", "proxy").strip().lower()
FORCE_SIGN = os.environ.get("MT_FORCE", "0") == "1"

LOGIN_URL = (f"{BASE_URL}/member.php?mod=logging&action=login"
             "&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login")
SIGN_PAGE = f"{BASE_URL}/k_misign-sign.html"
SIGN_API = f"{BASE_URL}/plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash={{0}}"
PROBE_URL = f"{BASE_URL}/forum.php?mod=guide&view=hot"

HEADERS = {
    'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'keep-alive',
}

IP_RE = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\s]\s*(\d{2,5})\s*$')

LOGIN_FAIL_RE = re.compile(r'登录失败|密码错误|用户名.*?不正确|密码.*?不正确|账号不存在|抱歉|您的账号|安全提问', re.I)
LOGIN_OK_RE = re.compile(r'登录成功|欢迎您回来|succeed', re.I)

SUCCESS_RE = re.compile(r'已签|签到成功|签到完成|签到已完成|恭喜|success|qiandao_success|获得', re.I)
FAIL_RE = re.compile(r'失败|错误|未登录|请登录|非法|请先登录|重新登录|异常', re.I)


def esa_get(session, url, **kw):
    """带 ESA acw 挑战处理的 GET（挑战识别与算法还原实现见 esa.py）"""
    kw.setdefault('timeout', TIMEOUT)
    return esa.get(session, url, logger=logger, **kw)


def esa_request(session, method, url, **kw):
    """带 ESA acw 挑战处理的任意方法请求"""
    kw.setdefault('timeout', TIMEOUT)
    return esa.request(session, method, url, logger=logger, **kw)


def is_phone_number(username):
    return re.match(r'^1[3-9]\d{9}$', username) is not None


def format_username(username):
    if is_phone_number(username) and len(username) == 11:
        return f"{username[:3]}****{username[-4:]}"
    return username


# ------------------------- 字段提取 -------------------------
FORMHASH_PATTERNS = [
    r'name=["\']formhash["\']\s+value=["\']([A-Za-z0-9]{4,16})["\']',
    r'value=["\']([A-Za-z0-9]{4,16})["\']\s+name=["\']formhash["\']',
    r'formhash["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{4,16})',
    r'formhash[\'"].*?value=[\'"](.*?)[\'"].*?/>',
]

LOGINHASH_PATTERNS = [
    r'loginhash["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{4,16})',
    r'loginhash.*?=(.*?)[\'"]>',
]


def _first_match(data, patterns):
    for p in patterns:
        m = re.search(p, data, re.IGNORECASE | re.UNICODE)
        if m and m.group(1):
            val = m.group(1).strip().strip('\'"')
            if val and len(val) <= 32:
                return val
    return ''


def formhash(data):
    return _first_match(data, FORMHASH_PATTERNS)


def loginhash(data):
    return _first_match(data, LOGINHASH_PATTERNS)


def cdata(data):
    """提取 <![CDATA[...]]> 内容，取不到就返回原文摘要"""
    m = re.search(r'<!\[CDATA\[(.*?)\]\]>', data, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(r'CDATA.*?\[(.*?)\]', data, re.IGNORECASE | re.DOTALL)
    if m and m.group(1).strip('[]'):
        return m.group(1).strip('[]').strip()
    plain = re.sub(r'<script.*?</script>', ' ', data, flags=re.IGNORECASE | re.DOTALL)
    plain = re.sub(r'<[^>]+>', ' ', plain)
    return re.sub(r'\s+', ' ', plain).strip()[:200]


# ------------------------- 代理 -------------------------
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


def _read_proxy_file(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = IP_RE.match(line)
                if not m:
                    continue
                ip, port = m.group(1), m.group(2)
                if validate_ip_port(ip, port):
                    out.append(f"{ip}:{port}")
    except Exception:
        pass
    return out


def _verify(proxy):
    proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
    start = time.time()
    try:
        s = requests.Session()
        s.headers.update(HEADERS)
        s.proxies = proxies
        r = esa_get(s, PROBE_URL, timeout=min(TIMEOUT, 12))
        ok = r.ok and r.status_code == 200 and not esa.is_challenge(r.text)
        return proxy, ok, int((time.time() - start) * 1000)
    except Exception:
        return proxy, False, -1


def load_proxies():
    """收集并验证可用代理，按响应耗时升序返回"""
    candidates = []
    seen = set()

    def add(items):
        for p in items:
            if p not in seen:
                seen.add(p)
                candidates.append(p)

    # 只用仓库内的国内代理池，不引入在线来源（海外 IP 会触发论坛滑块验证）
    add(_read_proxy_file("src/ips.txt"))
    add(_read_proxy_file("src/verify.txt"))

    candidates = candidates[:MAX_PROXY]
    if not candidates:
        logger.warning("没有可用代理候选")
        return []

    logger.info(f"开始验证 {len(candidates)} 个代理 ...")
    good = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futures = [ex.submit(_verify, p) for p in candidates]
        for fu in as_completed(futures):
            proxy, ok, ms = fu.result()
            if ok:
                good.append((proxy, ms))
    good.sort(key=lambda x: x[1])

    logger.info(f"可用代理 {len(good)} 个:")
    for i, (proxy, ms) in enumerate(good[:15], 1):
        logger.info(f"  {i}: {proxy} - {ms}ms")
    return [p for p, _ in good]


def direct_ok():
    """检测 runner 本机能否直连论坛"""
    try:
        s = requests.Session()
        s.headers.update(HEADERS)
        r = esa_get(s, PROBE_URL, timeout=min(TIMEOUT, 15))
        ok = r.ok and r.status_code == 200 and not esa.is_challenge(r.text)
        logger.info(f"直连检测: {'可用' if ok else '不可用'} (HTTP {r.status_code})")
        return ok
    except Exception as e:
        logger.warning(f"直连检测失败: {e}")
        return False


# ------------------------- 签到 -------------------------
def check_in(user, pwd, proxy=None):
    """proxy 为 None 表示直连。返回 True=成功/已签，False=失败"""
    tag = proxy or "直连"
    session = requests.Session()
    session.headers.update(HEADERS)
    if proxy:
        session.proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}

    logger.info(f"{format_username(user)} 开始签到（{tag}）")
    try:
        # 1. 取登录页，拿 loginhash / formhash
        r = esa_get(session, LOGIN_URL, timeout=TIMEOUT)
        r.encoding = r.apparent_encoding or 'utf-8'
        if not r.ok:
            logger.warning(f"{format_username(user)} 登录页获取失败 HTTP {r.status_code}")
            return False
        if esa.is_challenge(r.text):
            logger.warning(f"{format_username(user)} 仍停留在 ESA 挑战页，跳过该通道")
            return False

        _loginhash = loginhash(r.text)
        _formhash = formhash(r.text)
        if not _formhash:
            logger.warning(f"{format_username(user)} 未能提取 formhash，跳过该通道")
            return False

        # 2. 提交登录
        login_url = (f"{BASE_URL}/member.php?mod=logging&action=login&loginsubmit=yes"
                     f"&handlekey=login&loginhash={_loginhash}&inajax=1")
        data = {
            'formhash': _formhash,
            'referer': SIGN_PAGE,
            'fastloginfield': 'username',
            'username': user,
            'password': pwd,
            'questionid': '0',
            'answer': '',
            'agreebbrule': '',
        }
        r = esa_request(session, 'POST', login_url, data=data, timeout=TIMEOUT)
        r.encoding = r.apparent_encoding or 'utf-8'
        state = check_login(r.text)
        if state is False:
            logger.error(f"{format_username(user)} 登录失败，请检查账号密码")
            return "BAD_PWD"
        if state is None:
            logger.warning(f"{format_username(user)} 登录响应未知: {cdata(r.text)}")

        # 3. 进入签到页拿新的 formhash
        time.sleep(1)
        r = esa_get(session, SIGN_PAGE, timeout=TIMEOUT)
        r.encoding = r.apparent_encoding or 'utf-8'
        if not r.ok:
            logger.warning(f"{format_username(user)} 签到页获取失败 HTTP {r.status_code}")
            return False
        _formhash = formhash(r.text) or _formhash
        if not _formhash:
            logger.warning(f"{format_username(user)} 签到页未取到 formhash")
            return False

        # 4. 发起签到
        time.sleep(1)
        r = esa_get(session, SIGN_API.format(_formhash), timeout=TIMEOUT)
        r.encoding = r.apparent_encoding or 'utf-8'
        text = cdata(r.text)
        if SUCCESS_RE.search(text):
            logger.info(f"{format_username(user)} 签到成功: {text}")
            return True
        logger.warning(f"{format_username(user)} 签到未确认: {text}")
        if FAIL_RE.search(text):
            return False
        # 兜底：回查签到页是否已签
        chk = esa_get(session, SIGN_PAGE, timeout=TIMEOUT)
        chk.encoding = chk.apparent_encoding or 'utf-8'
        if SUCCESS_RE.search(chk.text) or '已签' in chk.text:
            logger.info(f"{format_username(user)} 回查确认已签到")
            return True
        return False
    except Exception as e:
        logger.warning(f"{format_username(user)} 异常({tag}): {type(e).__name__} {e}")
        return False


def check_login(text):
    """True=成功 False=失败 None=未知"""
    if LOGIN_FAIL_RE.search(text):
        return False
    if LOGIN_OK_RE.search(text):
        return True
    if '失败' in text:
        return False
    return None


def parse_accounts():
    raw = os.environ.get("ACCOUNTS", "")
    if not raw.strip():
        logger.error("GitHub Secrets 变量 ACCOUNTS 未设置")
        return None
    accounts = {}
    for line in raw.replace('\r', '').split('\n'):
        if ':' not in line:
            continue
        u, p = line.split(':', 1)
        u, p = u.strip(), p.strip()
        if u and p:
            accounts[u] = p
    if not accounts:
        logger.error("ACCOUNTS 格式有误，应为 user:pass（多账号换行分隔）")
        return None
    return accounts


def main():
    accounts = parse_accounts()
    if accounts is None:
        sys.exit(1)

    today = prefs.getTime()
    todo = {}
    for u, p in accounts.items():
        if not FORCE_SIGN and prefs.get(u, "") == today:
            logger.info(f"{format_username(u)} 今日已签，跳过")
            continue
        todo[u] = p

    if not todo:
        logger.info("所有账号今日均已完成签到")
        return 0

    logger.info(f"待签到账号 {len(todo)} 个")

    proxies = []
    can_direct = False
    if PROXY_MODE in ("auto", "proxy"):
        proxies = load_proxies()
    if PROXY_MODE in ("auto", "direct", "proxy"):
        # 只在代理不足时才探测直连（runner 在海外，直连易触发滑块）
        if PROXY_MODE == "direct" or not proxies:
            can_direct = direct_ok()

    # 国内代理始终排前面，直连仅作最后兜底
    channels = proxies + (["__direct__"] if can_direct else [])

    if not channels:
        logger.error("没有可用代理且直连不可用，无法签到")
        return 1

    logger.info(f"本次可用通道 {len(channels)} 个")

    failed = []
    bad_pwd = []
    keys = list(todo.keys())
    for i, user in enumerate(keys):
        if user not in todo:
            continue
        ok = False
        for ch in channels:
            proxy = None if ch == "__direct__" else ch
            res = check_in(user, todo[user], proxy)
            if res is True:
                prefs.put(user, today)
                todo.pop(user, None)
                ok = True
                break
            if res == "BAD_PWD":
                bad_pwd.append(user)
                todo.pop(user, None)
                break
            time.sleep(2)
        if not ok and user not in bad_pwd:
            failed.append(user)
        if i < len(keys) - 1:
            time.sleep(3)

    if bad_pwd:
        logger.error(f"账号密码有误: {', '.join(format_username(u) for u in bad_pwd)}")
    if failed:
        logger.error(f"以下账号签到失败: {', '.join(format_username(u) for u in failed)}")
    if bad_pwd or failed:
        return 1
    logger.info("全部账号签到完成")
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception as e:
        logger.error(f"运行异常: {type(e).__name__} {e}")
        code = 1
    prefs.save()
    sys.exit(code)
