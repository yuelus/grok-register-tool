"""
Microsoft Outlook/Graph API 邮件读取模块
从 GuJumpgate 项目的 microsoft-email.js 和 chatgpt2api 的 mail_provider.py 移植
支持 Graph API + Outlook REST API 双通道降级
"""

import re
import time
from datetime import datetime, timezone
from threading import Lock
from curl_cffi import requests

# --- Token 策略 (按成功率排序) ---
TOKEN_STRATEGIES = [
    {
        "name": "entra-consumers-default",
        "url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        "scope": "https://graph.microsoft.com/.default",
    },
    {
        "name": "entra-common-default",
        "url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "https://graph.microsoft.com/.default",
    },
    {
        "name": "entra-consumers-delegated",
        "url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        "scope": "offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read",
    },
    {
        "name": "entra-common-delegated",
        "url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read",
    },
]

# 传输通道优先级: graph → outlook
TRANSPORT_PLANS = [
    {"transport": "graph", "strategy_names": ["entra-consumers-default", "entra-common-default"]},
    {"transport": "outlook", "strategy_names": ["entra-consumers-default", "entra-common-default", "entra-consumers-delegated", "entra-common-delegated"]},
]

GRAPH_API_BASE = "https://graph.microsoft.com/v1.0/me/mailFolders"
OUTLOOK_API_BASE = "https://outlook.office.com/api/v2.0/me/mailfolders"

# xAI/Grok 相关发件人域名白名单
_XAI_SENDER_DOMAINS = (
    "x.ai", "x.com", "grok.com", "xai.com",
    "twitter.com", "tesla.com",
)
# xAI 相关关键词（发件人地址或主题中出现即认为相关）
_XAI_KEYWORDS = ("xai", "grok", "x.ai", "x.com")


def _is_xai_related(from_address, from_name="", subject=""):
    """判断邮件是否来自 xAI/Grok 相关发件人。"""
    addr = (from_address or "").lower().strip()
    name = (from_name or "").lower().strip()
    subj = (subject or "").lower()

    # 检查发件人域名
    for domain in _XAI_SENDER_DOMAINS:
        if addr.endswith("@" + domain) or addr.endswith("." + domain):
            return True

    # 检查发件人地址或名称中的关键词
    for kw in _XAI_KEYWORDS:
        if kw in addr or kw in name:
            return True

    # 检查主题中的关键词（xAI 验证码邮件通常主题含 xAI）
    for kw in _XAI_KEYWORDS:
        if kw in subj:
            return True

    return False

# --- Token 缓存 ---
_token_cache: dict[str, dict] = {}  # cache_key -> {access_token, refresh_token, expires_at}
_token_cache_guard = Lock()
TOKEN_CACHE_TTL_BUFFER = 60  # 提前 60 秒视为过期


def _get_strategy(name):
    for s in TOKEN_STRATEGIES:
        if s["name"] == name:
            return s
    return None


def _normalize_mailbox(mailbox="inbox"):
    m = (mailbox or "inbox").strip().lower()
    if m.startswith("junk"):
        return "junkemail"
    return "inbox"


def _cache_key(client_id, refresh_token):
    return f"{client_id}|{refresh_token}"


def _get_cached_token(client_id, refresh_token):
    key = _cache_key(client_id, refresh_token)
    with _token_cache_guard:
        cached = _token_cache.get(key)
        if cached and cached.get("expires_at", 0) > time.time():
            return cached
    return None


def _put_token_cache(client_id, refresh_token, access_token, new_refresh_token, expires_in):
    key = _cache_key(client_id, refresh_token)
    entry = {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "expires_at": time.time() + max(60, expires_in - TOKEN_CACHE_TTL_BUFFER),
    }
    with _token_cache_guard:
        _token_cache[key] = entry
        # 如果 refresh_token 轮转了，也用新 key 缓存
        if new_refresh_token and new_refresh_token != refresh_token:
            _token_cache[_cache_key(client_id, new_refresh_token)] = entry


def exchange_refresh_token(client_id, refresh_token, strategy_name=None, on_refresh_token_rotated=None):
    """用 refresh_token 换 access_token，带缓存和重试。"""
    # 先检查缓存
    cached = _get_cached_token(client_id, refresh_token)
    if cached:
        return {
            "access_token": cached["access_token"],
            "refresh_token": cached.get("refresh_token", refresh_token),
            "expires_in": int(cached["expires_at"] - time.time()),
            "token_strategy": "cached",
        }

    strategies = [_get_strategy(strategy_name)] if strategy_name else TOKEN_STRATEGIES
    last_err = None
    for strategy in strategies:
        if not strategy:
            continue
        body = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if strategy["scope"]:
            body["scope"] = strategy["scope"]

        # 带重试的请求 (AADSTS50196 / 429 / 5xx)
        for attempt in range(3):
            try:
                resp = requests.post(
                    strategy["url"],
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    access_token = data.get("access_token", "")
                    if not access_token:
                        last_err = f"{strategy['name']}: missing access_token"
                        break
                    new_rt = data.get("refresh_token", refresh_token)
                    expires_in = data.get("expires_in", 0)

                    # 缓存
                    _put_token_cache(client_id, refresh_token, access_token, new_rt, expires_in)

                    # 通知调用方 refresh_token 已轮转
                    if new_rt and new_rt != refresh_token and on_refresh_token_rotated:
                        try:
                            on_refresh_token_rotated(new_rt)
                        except Exception:
                            pass

                    return {
                        "access_token": access_token,
                        "refresh_token": new_rt,
                        "expires_in": expires_in,
                        "token_strategy": strategy["name"],
                    }

                resp_text = resp.text[:300]
                # 可重试的错误
                if "AADSTS50196" in resp_text or resp.status_code in (429, 500, 502, 503, 504):
                    time.sleep(2.5 + attempt * 2.5)
                    continue
                # 不可重试，跳到下一个 strategy
                last_err = f"{strategy['name']}: HTTP {resp.status_code} {resp_text[:200]}"
                break

            except Exception as e:
                last_err = f"{strategy['name']}: {e}"
                break  # 网络错误不重试，跳到下一个 strategy

    raise Exception(f"所有 token 策略均失败: {last_err}")


def _fetch_graph_messages(access_token, mailbox="inbox", top=5):
    """Graph API 读取邮件。"""
    mb = _normalize_mailbox(mailbox)
    url = (
        f"{GRAPH_API_BASE}/{mb}/messages"
        f"?$top={top}"
        f"&$select=id,internetMessageId,subject,from,bodyPreview,receivedDateTime,toRecipients,body"
        f"&$orderby=receivedDateTime desc"
    )
    resp = requests.get(
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise Exception(f"graph HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    return data.get("value", []) if isinstance(data, dict) else []


def _fetch_outlook_messages(access_token, mailbox="inbox", top=5):
    """Outlook REST API 读取邮件。"""
    mb = _normalize_mailbox(mailbox)
    url = (
        f"{OUTLOOK_API_BASE}/{mb}/messages"
        f"?$top={top}"
        f"&$select=Id,Subject,From,BodyPreview,Body,ReceivedDateTime,ToRecipients"
        f"&$orderby=ReceivedDateTime desc"
    )
    resp = requests.get(
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise Exception(f"outlook HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    return data.get("value", []) if isinstance(data, dict) else []


def _normalize_message(msg, mailbox="inbox"):
    """统一 Graph/Outlook 消息格式。"""
    from_addr = ""
    from_name = ""
    f = msg.get("from", {})
    if isinstance(f, dict):
        ea = f.get("emailAddress", {})
        from_addr = ea.get("address", "")
        from_name = ea.get("name", "")

    to_list = []
    for r in (msg.get("toRecipients") or []):
        ea = r.get("emailAddress", {})
        if ea.get("address"):
            to_list.append(ea["address"].lower())

    subject = msg.get("subject", "")
    preview = msg.get("bodyPreview", "")
    body_content = ""
    body = msg.get("body", {})
    if isinstance(body, dict):
        body_content = body.get("content", "")
    received = msg.get("receivedDateTime", "")
    msg_id = msg.get("id") or msg.get("Id") or msg.get("internetMessageId", "")

    return {
        "id": msg_id,
        "subject": subject,
        "from_address": from_addr.lower(),
        "from_name": from_name,
        "to": to_list,
        "body_preview": preview,
        "body_content": body_content,
        "received_at": received,
    }


def fetch_messages(client_id, refresh_token, mailbox="inbox", top=5, log_callback=None, on_refresh_token_rotated=None):
    """读取邮件，Graph → Outlook 双通道降级，返回 (messages, new_refresh_token)。"""
    last_err = None
    for plan in TRANSPORT_PLANS:
        for strategy_name in plan["strategy_names"]:
            try:
                token_data = exchange_refresh_token(
                    client_id, refresh_token, strategy_name,
                    on_refresh_token_rotated=on_refresh_token_rotated,
                )
                access_token = token_data["access_token"]
                new_rt = token_data.get("refresh_token", refresh_token)

                if plan["transport"] == "graph":
                    raw = _fetch_graph_messages(access_token, mailbox, top)
                else:
                    raw = _fetch_outlook_messages(access_token, mailbox, top)

                messages = [_normalize_message(m, mailbox) for m in raw]
                return messages, new_rt
            except Exception as e:
                last_err = f"{plan['transport']}/{strategy_name}: {e}"
                continue
    raise Exception(f"Microsoft 邮箱读取失败: {last_err}")


def fetch_messages_both_folders(client_id, refresh_token, top=10, log_callback=None, on_refresh_token_rotated=None):
    """同时读取 inbox + junkemail，合并去重后返回 (messages, new_refresh_token)。"""
    all_msgs = {}
    working_rt = refresh_token
    for mb in ("inbox", "junkemail"):
        try:
            msgs, working_rt = fetch_messages(
                client_id, working_rt, mailbox=mb, top=top,
                log_callback=log_callback,
                on_refresh_token_rotated=on_refresh_token_rotated,
            )
            for m in msgs:
                if m["id"] and m["id"] not in all_msgs:
                    all_msgs[m["id"]] = m
        except Exception:
            pass  # junk 失败不影响 inbox
    return list(all_msgs.values()), working_rt


def extract_verification_code(text, subject=""):
    """从邮件内容中提取验证码。

    优先级：
    1. xAI 格式: XXX-XXX xAI
    2. 通用 XXX-XXX 格式
    3. HTML 特殊样式 (background-color: #F3F3F3 中的 6 位数字)
    4. 中文验证码
    5. login code / enter this code
    6. code is: / code:
    7. 兜底: 独立6位数字
    """
    if not text:
        text = ""
    source = f"{subject}\n{text}"

    # xAI 格式: XXX-XXX xAI
    if subject:
        m = re.search(r"^([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI", subject, re.IGNORECASE)
        if m:
            return m.group(1)

    # 通用 XXX-XXX 格式
    m = re.search(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", source, re.IGNORECASE)
    if m:
        return m.group(1)

    # HTML 特殊样式: background-color: #F3F3F3 中的 6 位数字
    m = re.search(r"background-color:\s*#F3F3F3[^>]*>[\s\S]*?(\d{6})[\s\S]*?</p>", source, re.I)
    if m and m.group(1) != "177010":
        return m.group(1)

    # 中文验证码
    m = re.search(r"(?:代码为|验证码[^0-9]*?)[\s：:]*([0-9]{6})", source)
    if m:
        return m.group(1)

    # login code / enter this code
    m = re.search(r"(?:log-?in\s+code|enter\s+this\s+code)[^0-9]{0,24}([0-9]{6})", source, re.IGNORECASE)
    if m:
        return m.group(1)

    # code is: / code:
    m = re.search(r"code(?:\s+is|[\s:])+([0-9]{6})", source, re.IGNORECASE)
    if m:
        return m.group(1)

    # Verification code / code is
    m = re.search(r"(?:Verification code|code is)[:\s]*(\d{6})", source, re.I)
    if m and m.group(1) != "177010":
        return m.group(1)

    # 兜底: HTML 或文本中的独立6位数字 (排除 177010 误匹配)
    for code in re.findall(r">\s*(\d{6})\s*<|(?<![#&])\b(\d{6})\b", source):
        value = code[0] or code[1]
        if value and value != "177010":
            return value

    return ""


def fetch_verification_code(
    client_id,
    refresh_token,
    email=None,
    after_timestamp=None,
    max_retries=12,
    retry_delay=5.0,
    log_callback=None,
    cancel_callback=None,
    on_refresh_token_rotated=None,
):
    """带重试的验证码获取主函数。

    Args:
        client_id: Microsoft 应用客户端 ID
        refresh_token: 刷新令牌
        email: 收件人邮箱（用于过滤）
        after_timestamp: 只接受此时间戳之后的邮件 (ISO 格式或 unix timestamp)
        max_retries: 最大重试次数
        retry_delay: 重试间隔秒数
        log_callback: 日志回调
        cancel_callback: 取消回调
        on_refresh_token_rotated: refresh_token 轮转时的回调

    Returns:
        str: 验证码，失败返回空字符串
    """
    working_rt = refresh_token
    seen_ids = set()
    exclude_codes = set()

    # 自动设置时间过滤：只看开始轮询之后的邮件
    if after_timestamp is None:
        after_timestamp = datetime.now(tz=timezone.utc).isoformat()

    for attempt in range(1, max_retries + 1):
        if cancel_callback and cancel_callback():
            return ""

        if log_callback and attempt > 1:
            log_callback(f"[*] Outlook 轮询验证码 第{attempt}次...")

        try:
            # 同时检查收件箱和垃圾邮件
            messages, working_rt = fetch_messages_both_folders(
                client_id, working_rt, top=10,
                log_callback=log_callback,
                on_refresh_token_rotated=on_refresh_token_rotated,
            )
        except Exception as e:
            if log_callback:
                log_callback(f"[!] Outlook 读取邮件失败: {e}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            continue

        new_count = 0
        for msg in messages:
            if msg["id"] in seen_ids:
                continue
            new_count += 1

            from_addr = msg.get("from_address", "")
            from_name = msg.get("from_name", "")
            subject = msg.get("subject", "")

            # xAI 发件人校验：只处理来自 xAI/Grok 相关的邮件
            if not _is_xai_related(from_addr, from_name, subject):
                seen_ids.add(msg["id"])
                continue

            # 时间过滤：只看轮询开始之后的邮件
            received = msg.get("received_at", "")
            if received and after_timestamp:
                try:
                    if isinstance(after_timestamp, str):
                        if received < after_timestamp:
                            seen_ids.add(msg["id"])
                            continue
                    else:
                        dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
                        if dt.timestamp() < after_timestamp:
                            seen_ids.add(msg["id"])
                            continue
                except Exception:
                    pass

            # 收件人过滤
            if email:
                email_lower = email.lower()
                to_match = False
                for to_addr in msg.get("to", []):
                    if email_lower in to_addr.lower() or to_addr.lower() in email_lower:
                        to_match = True
                        break
                # 对于别名模式，也检查是否匹配基邮箱
                if not to_match and "+" in email_lower:
                    base_email = email_lower.split("+")[0] + "@" + email_lower.split("@")[-1]
                    for to_addr in msg.get("to", []):
                        if base_email in to_addr.lower():
                            to_match = True
                            break
                if not to_match:
                    seen_ids.add(msg["id"])
                    continue

            body = msg.get("body_content", "") or msg.get("body_preview", "")

            # 提取验证码
            code = extract_verification_code(body, subject)
            if code and code not in exclude_codes:
                if log_callback:
                    log_callback(f"[+] Outlook 验证码: {code} (来自: {from_addr})")
                return code

            seen_ids.add(msg["id"])

        if log_callback and new_count > 0:
            log_callback(f"[*] Outlook 本轮 {new_count} 封新邮件，均未匹配验证码")

        if attempt < max_retries:
            time.sleep(retry_delay)

    return ""
