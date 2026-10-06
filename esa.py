# -*- coding: utf-8 -*-
"""阿里云 ESA acw_sc__v2 JS 挑战处理（共享模块）

背景：
    bbs.binmt.cc 前置了阿里云 ESA 防护。首次访问任意页面会返回一段混淆 JS，
    浏览器执行后写入 cookie `acw_sc__v2` 并 location.reload()。
    纯 HTTP 客户端拿到的就是这段 JS —— 状态码 200，但没有 formhash、
    没有登录框，看起来"网络正常"实则请求根本没到业务逻辑。

解决：
    按页面里给出的置换数组 + 固定 key 做异或，还原 acw_sc__v2，写入 Session
    后重放一次请求。core_fix: 挑战识别、算法还原、单次重放、失败原样返回。
"""

import re
import time
from urllib.parse import urlparse

import requests

ESA_ARG1_RE = re.compile(r"var\s+arg1\s*=\s*['\"]([0-9A-Fa-f]+)['\"]")
ESA_SHUFFLE_RE = re.compile(r'for\s*\(\s*var\s+m\s*=\s*\[([^\]]+)\]')
ACW_KEY = "3000176000856006061501533003690027800375"

# 最多重放次数，防止站点行为变化时无限循环
MAX_REPLAY = 2


def parse_challenge(html):
    """识别 acw 挑战页 -> (arg1, shuffle)；不是挑战页返回 None"""
    if not html:
        return None
    a = ESA_ARG1_RE.search(html)
    s = ESA_SHUFFLE_RE.search(html)
    if not a or not s:
        return None
    try:
        shuffle = [int(x, 16) for x in s.group(1).split(',')]
    except ValueError:
        return None
    arg1 = a.group(1)
    if len(shuffle) != len(arg1):
        return None
    return arg1, shuffle


def is_challenge(html):
    return parse_challenge(html) is not None


def compute_token(arg1, shuffle):
    """按置换表重排 + 与固定 key 异或，还原 acw_sc__v2"""
    out = [''] * len(shuffle)
    for i, ch in enumerate(arg1):
        target = i + 1
        for z, val in enumerate(shuffle):
            if val == target:
                out[z] = ch
                break
    u = ''.join(out)
    token = ''
    for x in range(0, min(len(u), len(ACW_KEY)), 2):
        pair = format(int(u[x:x + 2], 16) ^ int(ACW_KEY[x:x + 2], 16), 'x')
        if len(pair) == 1:
            pair = '0' + pair
        token += pair
    return token


def _host(url):
    try:
        return urlparse(url).hostname or ''
    except Exception:
        return ''


def request(session, method, url, logger=None, **kw):
    """带挑战处理的请求：命中挑战则算 cookie 并重放，返回最终 Response"""
    r = session.request(method, url, **kw)
    for _ in range(MAX_REPLAY):
        if not is_challenge(r.text):
            return r
        arg1, shuffle = parse_challenge(r.text)
        token = compute_token(arg1, shuffle)
        if not token:
            return r
        if logger:
            logger.info(f"检测到 ESA acw 挑战，正在计算 cookie ({len(token)} 位)")
        host = _host(url)
        try:
            if host:
                session.cookies.set('acw_sc__v2', token, domain=host, path='/')
            else:
                session.cookies.set('acw_sc__v2', token, path='/')
        except Exception:
            session.cookies.set('acw_sc__v2', token, path='/')
        time.sleep(1)
        r = session.request(method, url, **kw)
    if not is_challenge(r.text) and logger:
        logger.info("ESA 挑战已通过")
    return r


def get(session, url, **kw):
    return request(session, 'GET', url, **kw)


def probe(url, headers, proxies=None, timeout=15, logger=None):
    """独立探测：判断通道能否真正拿到业务页面（而非挑战页）"""
    s = requests.Session()
    s.headers.update(headers)
    if proxies:
        s.proxies = proxies
    try:
        r = get(s, url, timeout=timeout)
        if r.status_code != 200:
            return False
        # 仍停在挑战页 = 通道实际不可用
        return not is_challenge(r.text)
    except Exception:
        return False