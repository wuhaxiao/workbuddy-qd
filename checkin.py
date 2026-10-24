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
import time

import requests

API_HOST = "https://copilot.tencent.com"
STATUS_URL = API_HOST + "/v2/billing/meter/checkin-activity-status"
CHECKIN_URL = API_HOST + "/v2/billing/meter/daily-checkin"
RENEW_URL = API_HOST + "/v2/plugin/auth/token/refresh"
X_DOMAIN = "www.workbuddy.cn"

# accessToken 剩不到这么多秒就先续期（避免签到时正好过期）
RENEW_AHEAD_SEC = 3 * 86400

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


def token_exp(token):
    """解出 JWT 的 exp 时间戳；失败返回 0。"""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return int(json.loads(base64.urlsafe_b64decode(seg)).get("exp") or 0)
    except Exception:  # noqa: BLE001
        return 0


# ─── 离线续期 ────────────────────────────────────────
def renew(refresh_token, domain=X_DOMAIN):
    """用 refresh token 换新的 accessToken / refreshToken。

    走客户端同款业务接口，无需 client_secret：
        POST /v2/plugin/auth/token/refresh
        X-Domain / X-Refresh-Token / X-Auth-Refresh-Source: plugin

    返回 (data, err)。注意 refreshToken 每次都会轮换，旧值立即作废。
    """
    if not refresh_token:
        return None, "refresh token 为空"
    headers = {
        "X-Domain": domain or X_DOMAIN,
        "X-Refresh-Token": refresh_token,
        "X-Auth-Refresh-Source": "plugin",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": UA,
    }
    try:
        resp = requests.post(RENEW_URL, headers=headers, data="{}", timeout=25)
    except Exception as e:  # noqa: BLE001
        return None, "网络错误: %s" % e
    if resp.status_code != 200:
        return None, "HTTP %s" % resp.status_code
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return None, "响应非 JSON"
    if body.get("code") != 0:
        return None, "code=%s %s" % (body.get("code"), body.get("msg"))
    data = body.get("data") or {}
    if not data.get("accessToken"):
        return None, "响应缺少 accessToken"
    return data, None


def can_persist():
    """能否在续期后把新 refresh token 写回仓库 Secret。

    必须能回写才允许在云端续期：refresh token 是轮换式的，
    续期一次旧值就作废，若写不回去，下一轮必然 invalid_grant 断链。
    """
    if not (os.environ.get("GH_PAT") or "").strip():
        return False
    if not (os.environ.get("GH_REPO") or "").strip():
        return False
    try:
        import nacl  # noqa: F401
        return True
    except ImportError:
        return False


def ensure_token(acct):
    """确保账号有可用 accessToken；快过期则自动续期。

    返回 (ok, note)。续期成功时会在 acct 上打 _renewed 标记，
    以便主流程在结束时把轮换后的 refresh token 写回 Secret。
    """
    tok = acct.get("token") or ""
    rt = acct.get("refreshToken") or acct.get("rt") or ""
    exp = token_exp(tok)
    now = time.time()

    if tok and exp and exp - now > RENEW_AHEAD_SEC:
        return True, ""
    if not rt:
        # 没有 refresh token：只能硬着头皮试，过期就会 401
        return (True, "") if tok else (False, "既无 token 也无 refreshToken")

    # 关键闸门：写不回 Secret 就绝不续期，避免把唯一有效的 refresh token 作废
    if not can_persist():
        return False, "该账号需续期，但云端无法回写 Secret（未配 GH_PAT）——请本地 python wb_renew.py"

    data, err = renew(rt, acct.get("domain") or X_DOMAIN)
    if err:
        return False, "续期失败: %s" % err
    acct["token"] = data["accessToken"]
    acct["refreshToken"] = data.get("refreshToken") or rt
    acct["_renewed"] = True
    return True, "已续期"


def secret_payload(accounts):
    """构造写回 Secret 用的精简 JSON（只保留必要字段）。"""
    out = []
    for a in accounts:
        out.append({
            "name": a.get("name", ""),
            "token": a.get("token", ""),
            "refreshToken": a.get("refreshToken") or a.get("rt") or "",
        })
    return json.dumps({"accounts": out}, ensure_ascii=False, separators=(",", ":"))


def push_secret(accounts):
    """把续期后的账号写回仓库 Secret（需要 GH_PAT + GH_REPO）。

    失败只告警不中断：签到本身已经完成，Secret 留到下次本地同步再修。
    """
    pat = (os.environ.get("GH_PAT") or "").strip()
    repo = (os.environ.get("GH_REPO") or "").strip()
    if not pat or not repo:
        print("[i] 未配置 GH_PAT/GH_REPO，跳过 Secret 回写（续期结果本次有效）")
        return "skipped"
    try:
        from nacl import public
    except ImportError:
        print("[W] 缺少 pynacl，无法回写 Secret（pip install pynacl）")
        return "no-pynacl"

    api = "https://api.github.com/repos/%s/actions/secrets" % repo
    hdr = {"Authorization": "Bearer %s" % pat,
           "Accept": "application/vnd.github+json",
           "X-GitHub-Api-Version": "2022-11-28"}
    name = os.environ.get("SECRET_NAME", "WORKBUDDY_ACCOUNTS")
    try:
        k = requests.get(api + "/public-key", headers=hdr, timeout=20)
        if k.status_code != 200:
            print("[W] 取得 Secret 公钥失败 HTTP %s" % k.status_code)
            return "key-fail"
        pk = k.json()

        raw = base64.b64decode(pk["key"])
        sealed = public.SealedBox(public.PublicKey(raw))
        enc = base64.b64encode(sealed.encrypt(secret_payload(accounts).encode())).decode()

        r = requests.put(api + "/" + name,
                         headers=hdr,
                         json={"encrypted_value": enc, "key_id": pk["key_id"]},
                         timeout=20)
        if r.status_code in (201, 204):
            print("[i] 已把续期后的 token 写回 Secret %s" % name)
            return "ok"
        print("[W] 回写 Secret 失败 HTTP %s: %s" % (r.status_code, r.text[:160]))
        return "fail"
    except Exception as e:  # noqa: BLE001
        print("[W] 回写 Secret 异常: %s" % e)
        return "error"


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
    # 一眼看出云端能不能自主续期（缺 GH_PAT 时会退化成只签到，不续期）
    print("自动续期: %s" % ("已启用（可回写 Secret）"
                          if can_persist() else "未启用（缺 GH_PAT / GH_REPO / pynacl）"))
    lines = []
    summary = {"ok": 0, "already": 0, "expired": 0, "failed": 0}
    renewed = 0
    for acct in accounts:
        name = acct.get("name", "?")
        ok, note = ensure_token(acct)
        if ok and acct.get("_renewed"):
            renewed += 1
            print("♻️ %s: %s" % (mask(name), note))
        if not ok:
            summary["expired"] += 1
            print("⚠️ %s: %s" % (mask(name), note))
            lines.append("⚠️ %s: %s" % (name, note))
            continue
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
    if renewed:
        print("本轮续期 %d 个账号，正在回写 Secret…" % renewed)
        push_secret(accounts)
    push("WorkBuddy 签到", "\n".join(lines))


if __name__ == "__main__":
    main()
