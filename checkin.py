#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkBuddy 每日自动签到（无头版，供 GitHub Actions / 任务计划程序调用）
=====================================================================
适配 2026-10 版接口（WorkBuddy 5.7.x）。

接口契约（2026-10 实测）
------------------------
  POST /v2/billing/meter/checkin-activity-status   查询签到状态
  POST /v2/billing/meter/daily-checkin             执行签到（幂等）

  必需请求头：
      Authorization: Bearer <JWT>
      X-User-Id:  <uid>              ← 2026-10 新增；缺失 → 网关 401
      X-Domain:   www.workbuddy.cn   ← 2026-10 新增；缺失 → 网关 401
      User-Agent: 浏览器 UA           ← 服务端校验；用脚本默认 UA 会被拦

  返回示例：
      已签到 -> {"code":10001,"msg":"今天已签到，请明天再来"}
      成功   -> {"code":0,"msg":"签到成功",...}

账号来源（二选一）
------------------
  1) 环境变量 WORKBUDDY_ACCOUNTS：形如 {"accounts":[{"name":..,"token":..},...]}
  2) 本地文件 accounts.json / 签到token.json（便于本地调试）

  uid 若账号里没给，会自动从 JWT 的 sub 解出，**无需手工填**。

依赖: requests
"""

import base64
import json
import os
import sys

import requests

API_HOST = "https://copilot.tencent.com"
STATUS_URL = API_HOST + "/v2/billing/meter/checkin-activity-status"
CHECKIN_URL = API_HOST + "/v2/billing/meter/daily-checkin"
X_DOMAIN = "www.workbuddy.cn"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def load_accounts():
    """优先读环境变量 WORKBUDDY_ACCOUNTS，否则退回本地 JSON 文件。"""
    raw = os.environ.get("WORKBUDDY_ACCOUNTS", "").strip()
    if raw:
        try:
            return json.loads(raw).get("accounts", [])
        except Exception as e:  # noqa: BLE001
            print("[E] WORKBUDDY_ACCOUNTS 不是合法 JSON: %s" % e, file=sys.stderr)

    for path in ("accounts.json", "签到token.json"):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f).get("accounts", [])
            except Exception as e:  # noqa: BLE001
                print("[E] 读取 %s 失败: %s" % (path, e), file=sys.stderr)
    return []


def uid_from_token(token):
    """从 JWT payload 的 sub 解出 uid；失败返回空串。"""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg)).get("sub", "") or ""
    except Exception:  # noqa: BLE001
        return ""


def build_headers(token, uid=""):
    uid = uid or uid_from_token(token)
    return {
        "Authorization": "Bearer %s" % token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": UA,
        "X-User-Id": uid,            # 2026-10 新增，必需
        "X-Domain": X_DOMAIN,        # 2026-10 新增，必需
        "Origin": API_HOST,
        "Referer": API_HOST + "/",
    }


def classify(resp):
    """把响应归类为 (status, detail)。status ∈ ok / already / expired / failed。"""
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        data = {}
    code = data.get("code")
    msg = str(data.get("msg", ""))
    text = msg.lower()

    if resp.status_code == 200 and ("成功" in msg or code in (0, 200)):
        return "ok", (msg or "签到成功")
    if code == 10001 or "已签到" in msg or "请明天" in msg:
        return "already", (msg or "今日已签")
    if any(k in msg for k in ("失效", "过期", "无效", "expired", "invalid")):
        return "expired", (msg or "Token 失效")
    if resp.status_code == 401:
        return "expired", "HTTP 401（token 失效或缺少 X-User-Id / X-Domain）"
    if resp.status_code == 200:
        return "already", (msg or "今日已签(推断)")
    return "failed", "HTTP %s %s" % (resp.status_code, msg or resp.text[:120])


def do_checkin(acct):
    name = acct.get("name", "?")
    token = acct.get("token", "")
    if not token:
        return "failed", "缺少 token"
    try:
        resp = requests.post(
            CHECKIN_URL,
            headers=build_headers(token, acct.get("uid", "")),
            json=[],
            timeout=25,
        )
    except Exception as e:  # noqa: BLE001
        return "failed", "网络错误: %s" % e
    return classify(resp)


def push(title, content):
    """可选：PushPlus / Server酱 微信推送。"""
    token = os.environ.get("PUSHPLUS_TOKEN")
    if token:
        try:
            requests.post(
                "http://www.pushplus.plus/send",
                json={"token": token, "title": title, "content": content},
                timeout=15,
            )
        except Exception:  # noqa: BLE001
            pass
    key = os.environ.get("SERVERCHAN_KEY")
    if key:
        try:
            requests.post(
                "https://sctapi.ftqq.com/%s.send" % key,
                data={"title": title, "desp": content},
                timeout=15,
            )
        except Exception:  # noqa: BLE001
            pass


def mask(name):
    """脱敏账号名，避免在公开的 Actions 日志里暴露手机号。"""
    s = str(name)
    if len(s) == 11 and s.isdigit():
        return s[:3] + "****" + s[7:]
    if len(s) > 4:
        return s[:2] + "***" + s[-2:]
    return s


def main():
    accounts = load_accounts()
    if not accounts:
        print("[E] 没有可用账号，请配置 WORKBUDDY_ACCOUNTS 或本地 accounts.json")
        sys.exit(1)

    print("=== 开始签到，共 %d 个账号 ===" % len(accounts))
    lines = []
    summary = {"ok": 0, "already": 0, "expired": 0, "failed": 0}
    for acct in accounts:
        name = acct.get("name", "?")
        status, detail = do_checkin(acct)
        summary[status] += 1
        icon = {"ok": "✅", "already": "🟢", "expired": "⚠️", "failed": "❌"}[status]
        # 控制台/Actions 日志脱敏；微信推送里保留完整账号名便于识别
        print("%s %s: %s" % (icon, mask(name), detail))
        lines.append("%s %s: %s" % (icon, name, detail))

    total = ("签到完成 | 成功 %d / 已签 %d / 失效 %d / 失败 %d"
             % (summary["ok"], summary["already"], summary["expired"], summary["failed"]))
    print(total)
    lines.append(total)
    push("WorkBuddy 签到", "\n".join(lines))


if __name__ == "__main__":
    main()
