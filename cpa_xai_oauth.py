"""DrissionPage-based driver for the xAI OAuth → CPA-import flow.

Why this exists: Cloudflare Turnstile blocks Chrome-extension synthetic clicks
(isTrusted=false) and Playwright/patchright is also detected via the CDP
screenX/screenY=0 leak. DrissionPage drives Chromium over CDP too, but here we
side-load the `turnstilePatch` extension that patches MouseEvent.screenX/Y at
document_start in every frame. With that patch in place, Turnstile's
non-interactive challenge accepts the click DrissionPage performs against the
checkbox inside the Cloudflare iframe's shadow-root.

Modes:
  --mode self     : we generate PKCE locally, drive login, exchange the code,
                    build the xai-{email}.json record, and upload it to CPA via
                    POST /v0/management/auth-files. Self-contained.
  --mode external : you paste an authorize URL (e.g. one CPA's UI just gave you,
                    where CPA holds the code_verifier). We just drive the login
                    and capture the callback URL — paste it back into the CPA
                    UI's "回调 URL 或授权码" field. We never touch the verifier.

Run (uses the grok-register-tool venv where DrissionPage + curl_cffi already live):
  G:/AIProgram/grok-register-tool/.venv/Scripts/python.exe \
      G:/AIProgram/cap-xai-oauth/extension/.claude/dp_oauth.py \
      --mode self --email ... --password ... \
      --cap-base-url http://192.168.1.160:8317 --management-key cliproxy2026
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import secrets
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlparse

from DrissionPage import Chromium, ChromiumOptions
from curl_cffi import requests as cffi

# ---- frozen OAuth params (mirror cap_xai_oauth/constants.py) ----
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
SCOPE = "openid profile email offline_access grok-cli:access api:access"
REFERRER = "cli-proxy-api"
PLAN = "generic"
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 56121
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}/callback"
AUTHORIZE_URL_BASE = "https://auth.x.ai/oauth2/authorize"
TOKEN_URL = "https://auth.x.ai/oauth2/token"


def redirect_uri_for(port: int) -> str:
    return f"http://{CALLBACK_HOST}:{port}/callback"
API_BASE_URL = "https://api.x.ai/v1"
AUTH_FILE_TYPE = "xai"
AUTH_FILE_KIND = "oauth"
TOKEN_TYPE = "Bearer"

DEFAULT_EMAIL = "3mx78bpbvb@strongz.online"
DEFAULT_PASSWORD = "Ne75fa681!a7#XGFP_yZU"
DEFAULT_CAP_BASE = "http://192.168.1.160:8317"
DEFAULT_MGMT_KEY = "cliproxy2026"

EXTENSION_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "turnstilePatch"))


def log(msg: str) -> None:
    print(f"[dp] {msg}", flush=True)


class AuthCredentialError(Exception):
    """Raised when the xAI login form reports invalid email/password — the
    GUI uses this to mark the account 'failed: bad credentials' and move on
    rather than waiting for the timeout to elapse.
    """


def make_browser() -> Chromium:
    """Spin up a fresh Chromium with the turnstilePatch extension. We use
    DrissionPage's auto_port() which already gives each worker its own
    per-port user-data-dir under %TEMP%/DrissionPage/userData/<port>/, so
    concurrent browsers don't share cookies or extension storage.

    NB: we do NOT use a brand-new mkdtemp dir per account — empirically,
    Cloudflare Turnstile rejects tokens from cold profiles with no history,
    so warm-on-second-run profiles end up reliably solving where pristine
    ones fail with "[internal] Failed to verify Cloudflare turnstile token."
    """
    options = ChromiumOptions()
    options.auto_port()
    options.set_timeouts(base=1)
    if os.path.isdir(EXTENSION_PATH):
        options.add_extension(EXTENSION_PATH)
        log(f"loaded extension from {EXTENSION_PATH}")
    else:
        log(f"WARNING: turnstilePatch not found at {EXTENSION_PATH}")
    return Chromium(options)


# ---------- step 1: click "log in with email" if shown ----------
JS_CLICK_LOGIN_WITH_EMAIL = r"""
function isVisible(n){if(!n)return false;const s=getComputedStyle(n);if(s.display==='none'||s.visibility==='hidden'||s.opacity==='0')return false;const r=n.getBoundingClientRect();return r.width>0&&r.height>0;}
const cands = Array.from(document.querySelectorAll('button, a, [role=button]')).filter(isVisible);
const target = cands.find(n => {
  const t = (n.innerText||n.textContent||'').replace(/\s+/g,'').toLowerCase();
  return t.includes('loginwithemail') || t.includes('signinwithemail') || t.includes('continuewithemail') || t.includes('使用邮箱');
});
if (!target) return false;
target.scrollIntoView({block:'center'});
target.click();
return true;
"""


# ---------- step 2: fill email, click Next/Continue ----------
JS_FILL_EMAIL_AND_CONTINUE = r"""
const email = arguments[0];
function isVisible(n){if(!n)return false;const s=getComputedStyle(n);if(s.display==='none'||s.visibility==='hidden'||s.opacity==='0')return false;const r=n.getBoundingClientRect();return r.width>0&&r.height>0;}
function setVal(input, value){
  input.focus(); input.click();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  const tracker = input._valueTracker;
  if (tracker) tracker.setValue('');
  if (setter) setter.call(input, value); else input.value = value;
  input.dispatchEvent(new InputEvent('beforeinput',{bubbles:true,data:value,inputType:'insertText'}));
  input.dispatchEvent(new InputEvent('input',{bubbles:true,data:value,inputType:'insertText'}));
  input.dispatchEvent(new Event('change',{bubbles:true}));
}
const inp = Array.from(document.querySelectorAll(
  "input[type='email'], input[name='email'], input[autocomplete='username'], input[autocomplete='email'], input[data-testid='email']"
)).find(n => isVisible(n) && !n.disabled && !n.readOnly);
if (!inp) return 'no-email-input';
if ((inp.value||'').trim().toLowerCase() !== String(email).toLowerCase()) {
  setVal(inp, email);
}
inp.blur();
const buttons = Array.from(document.querySelectorAll('button[type=submit], button, [role=button]')).filter(n => isVisible(n) && !n.disabled && n.getAttribute('aria-disabled') !== 'true');
const btn = buttons.find(n => {
  const t = (n.innerText||n.textContent||'').replace(/\s+/g,'').toLowerCase();
  return /^(next|continue|signin|login|登录|继续|下一步)$/.test(t);
});
if (!btn) return 'filled-no-button';
btn.click();
return 'clicked';
"""


# ---------- step 3: fill password (don't submit yet — Turnstile must clear first) ----------
JS_FILL_PASSWORD = r"""
const password = arguments[0];
function isVisible(n){if(!n)return false;const s=getComputedStyle(n);if(s.display==='none'||s.visibility==='hidden'||s.opacity==='0')return false;const r=n.getBoundingClientRect();return r.width>0&&r.height>0;}
function setVal(input, value){
  input.focus(); input.click();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  const tracker = input._valueTracker;
  if (tracker) tracker.setValue('');
  if (setter) setter.call(input, value); else input.value = value;
  input.dispatchEvent(new InputEvent('beforeinput',{bubbles:true,data:value,inputType:'insertText'}));
  input.dispatchEvent(new InputEvent('input',{bubbles:true,data:value,inputType:'insertText'}));
  input.dispatchEvent(new Event('change',{bubbles:true}));
}
const inp = Array.from(document.querySelectorAll("input[type='password'], input[name='password'], input[autocomplete='current-password']")).find(n => isVisible(n) && !n.disabled && !n.readOnly);
if (!inp) return 'no-password-input';
if (!(inp.value||'')) setVal(inp, password);
inp.blur();
return 'filled';
"""


# ---------- check Turnstile state ----------
JS_TURNSTILE_STATUS = r"""
const cfInput = document.querySelector("input[name='cf-turnstile-response'], input[name='cf_chl_resp']");
const present = !!cfInput
  || !!document.querySelector("iframe[src*='turnstile'], iframe[src*='challenges.cloudflare'], div.cf-turnstile, [data-sitekey], script[src*='turnstile']");
const token = String((cfInput && cfInput.value) || '').trim();
let turnstileResp = '';
try { if (window.turnstile && typeof turnstile.getResponse === 'function') turnstileResp = String(turnstile.getResponse() || '').trim(); } catch(e) {}
const finalToken = token || turnstileResp;
return JSON.stringify({ present: !!present, token_len: finalToken.length });
"""


# ---------- detect "wrong credentials" error message on the page ----------
JS_DETECT_AUTH_ERROR = r"""
const raw = (document.body && document.body.innerText || '');
const txt = raw.toLowerCase();
const literals = [
  'invalid email or password',
  'incorrect email or password',
  'incorrect password',
  'wrong password',
  "couldn't sign you in",
  "couldn't log you in",
  'check your email or password',
  'email or password is incorrect',
  'email or password is wrong',
  'authentication failed',
];
for (const p of literals) {
  if (txt.includes(p)) return p;
}
// Chinese forms — observed: "错误的邮箱地址或密码。"
// Also tolerate variants with 账号/账户, missing 地址, or trailing 错误/不正确/无效.
const regexes = [
  /错误的邮箱[^\s。!.]*?(地址)?[^\s。!.]*?密码/,
  /错误的密码/,
  /邮箱(地址)?\s*或\s*密码/,
  /账[号户]\s*或\s*密码/,
  /(邮箱|账[号户]|密码)\s*(错误|不正确|无效)/,
  /密码\s*不\s*正确/,
];
for (const r of regexes) {
  const m = raw.match(r);
  if (m) return m[0];
}
return '';
"""


# ---------- step 4: click submit on the password page ----------
JS_SUBMIT_PASSWORD = r"""
function isVisible(n){if(!n)return false;const s=getComputedStyle(n);if(s.display==='none'||s.visibility==='hidden'||s.opacity==='0')return false;const r=n.getBoundingClientRect();return r.width>0&&r.height>0;}
const buttons = Array.from(document.querySelectorAll('button[type=submit], button, [role=button]')).filter(n => isVisible(n) && !n.disabled && n.getAttribute('aria-disabled') !== 'true');
const btn = buttons.find(n => {
  const t = (n.innerText||n.textContent||'').replace(/\s+/g,'').toLowerCase();
  return /^(signin|login|continue|submit|登录|继续)$/.test(t);
});
if (!btn) return 'no-submit-button';
btn.click();
return 'clicked';
"""


# ---------- step 5: click Authorize / Allow on the consent page ----------
JS_CLICK_CONSENT = r"""
function isVisible(n){if(!n)return false;const s=getComputedStyle(n);if(s.display==='none'||s.visibility==='hidden'||s.opacity==='0')return false;const r=n.getBoundingClientRect();return r.width>0&&r.height>0;}
const buttons = Array.from(document.querySelectorAll('button, [role=button]')).filter(n => isVisible(n) && !n.disabled && n.getAttribute('aria-disabled') !== 'true');
const btn = buttons.find(n => {
  const t = (n.innerText||n.textContent||'').replace(/\s+/g,'').toLowerCase();
  return /^(authorize|allow|approve|accept|continue|授权|允许|批准)$/.test(t);
});
if (!btn) return 'no-consent-button';
btn.click();
return 'clicked';
"""


def drive_turnstile(page, log_callback=log, deadline_s=120, stop_event=None) -> bool:
    """Drive the Turnstile checkbox using the same shadow-root trick as
    grok-register-tool. Returns True when cf-turnstile-response is populated.
    Returns False immediately when stop_event is set so the GUI's Stop button
    doesn't have to wait for the full deadline."""
    last_attempt = 0.0
    deadline = time.time() + deadline_s

    def _stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    while time.time() < deadline:
        if _stopped():
            return False
        try:
            status = page.run_js(JS_TURNSTILE_STATUS)
            try:
                info = json.loads(status) if isinstance(status, str) else status
            except Exception:
                info = {"present": False, "token_len": 0}
            if not info.get("present"):
                return True  # nothing to solve
            if info.get("token_len", 0) >= 80:
                log_callback(f"turnstile solved (token_len={info['token_len']})")
                return True
            now = time.time()
            if now - last_attempt < 1.5:
                if _stopped():
                    return False
                time.sleep(0.3)
                continue
            last_attempt = now

            # Try to click the actual checkbox inside the cloudflare iframe's
            # shadow-root. This is the trick that works with the screenX/Y patch.
            challenge_input = page.ele("@name=cf-turnstile-response", timeout=0.5)
            clicked = False
            if challenge_input:
                try:
                    wrapper = challenge_input.parent()
                    iframe = None
                    try:
                        iframe = wrapper.shadow_root.ele("tag:iframe", timeout=0.5)
                    except Exception:
                        iframe = None
                    if iframe is None:
                        try:
                            iframe = page.ele("tag:iframe@@src*=challenges.cloudflare", timeout=0.5)
                        except Exception:
                            iframe = None
                    if iframe:
                        try:
                            body = iframe.ele("tag:body", timeout=1)
                            sr = body.shadow_root if body else None
                            cb = sr.ele("tag:input", timeout=1) if sr else None
                            if cb:
                                cb.click()
                                clicked = True
                        except Exception as e:
                            log_callback(f"shadow-root click failed: {e}")
                except Exception as e:
                    log_callback(f"iframe locate failed: {e}")
            if not clicked:
                # fallback: try clicking the visible turnstile container directly
                try:
                    page.run_js(
                        """
const nodes = Array.from(document.querySelectorAll('div,span,iframe')).filter((n) => {
  const txt = (n.className||'')+' '+(n.id||'')+' '+(n.getAttribute && n.getAttribute('src') || '');
  return String(txt).toLowerCase().includes('turnstile') || String(txt).toLowerCase().includes('cf-turnstile');
});
if (nodes.length && typeof nodes[0].click === 'function') nodes[0].click();
                        """
                    )
                except Exception:
                    pass
        except Exception as e:
            log_callback(f"turnstile loop error: {e}")
        if _stopped():
            return False
        time.sleep(0.7)
    log_callback("turnstile timeout — token not populated")
    return False


def wait_for(predicate, timeout, interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = predicate()
            if v:
                return v
        except Exception:
            pass
        time.sleep(interval)
    return None


# ---------- PKCE / token exchange / record / upload ----------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def make_pkce() -> dict:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return {
        "verifier": verifier,
        "challenge": challenge,
        "state": secrets.token_hex(16),
        "nonce": secrets.token_hex(16),
    }


def build_authorize_url(pkce: dict, redirect_uri: str = REDIRECT_URI) -> str:
    params = {
        "client_id": CLIENT_ID,
        "code_challenge": pkce["challenge"],
        "code_challenge_method": "S256",
        "nonce": pkce["nonce"],
        "plan": PLAN,
        "redirect_uri": redirect_uri,
        "referrer": REFERRER,
        "response_type": "code",
        "scope": SCOPE,
        "state": pkce["state"],
    }
    return f"{AUTHORIZE_URL_BASE}?{urlencode(params)}"


def exchange_code(code: str, verifier: str, redirect_uri: str = REDIRECT_URI) -> dict:
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }
    resp = cffi.post(
        TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urlencode(data),
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"token exchange failed {resp.status_code}: {resp.text[:300]}")
    return resp.json()


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    seg = parts[1]
    pad = "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg + pad))


def build_auth_record(token_json: dict, fallback_email: str,
                       redirect_uri: str = REDIRECT_URI) -> dict:
    access_payload = _decode_jwt_payload(token_json["access_token"])
    sub = access_payload.get("sub") or access_payload.get("principal_id") or ""

    email = ""
    if token_json.get("id_token"):
        try:
            email = (_decode_jwt_payload(token_json["id_token"]).get("email") or "")
        except Exception:
            email = ""
    if not email:
        email = access_payload.get("email") or ""
    if not email:
        email = (fallback_email or "").strip()
    if not email:
        raise RuntimeError("could not derive email from id_token / access_token")

    expires_in = int(token_json.get("expires_in") or 0)
    now = time.time()
    expired_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + expires_in))
    last_refresh_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    return {
        "access_token": token_json["access_token"],
        "auth_kind": AUTH_FILE_KIND,
        "base_url": API_BASE_URL,
        "disabled": False,
        "email": email,
        "expired": expired_iso,
        "expires_in": expires_in,
        "id_token": token_json.get("id_token", "") or "",
        "last_refresh": last_refresh_iso,
        "redirect_uri": redirect_uri,
        "refresh_token": token_json.get("refresh_token", "") or "",
        "sub": sub,
        "token_endpoint": TOKEN_URL,
        "token_type": token_json.get("token_type") or TOKEN_TYPE,
        "type": AUTH_FILE_TYPE,
    }


def upload_auth_file(record: dict, cap_base_url: str, management_key: str) -> dict:
    """POST multipart to /v0/management/auth-files. Filename must end in .json.
    curl_cffi requires CurlMime instead of requests-style files= kwargs.
    """
    from curl_cffi import CurlMime

    file_name = f"xai-{record['email']}.json"
    blob = json.dumps(record, ensure_ascii=False).encode("utf-8")
    base = cap_base_url.rstrip("/")
    url = f"{base}/v0/management/auth-files"
    mp = CurlMime()
    mp.addpart(
        name="file",
        content_type="application/json",
        filename=file_name,
        data=blob,
    )
    headers = {"Authorization": f"Bearer {management_key}"}
    resp = cffi.post(url, headers=headers, multipart=mp, timeout=60)
    text = resp.text
    if resp.status_code >= 400:
        raise RuntimeError(f"upload failed {resp.status_code}: {text[:500]}")
    return {"file_name": file_name, "status": resp.status_code, "body": text[:500]}


# ---------- local callback server (self-mode) ----------

class _ReuseTCPServer(socketserver.TCPServer):
    """Allow rebind without TIME_WAIT delay between batch iterations."""
    allow_reuse_address = True


class _CallbackServer:
    """Tiny in-process HTTP server that accepts the OAuth redirect and stores
    the query string. Used in self-mode so Chrome's redirect actually receives
    200 OK instead of ERR_CONNECTION_REFUSED — that way we always capture the
    code even if the CDP listener races.
    """

    def __init__(self, host: str, port: int, path: str):
        self.host = host
        self.port = port
        self.path = path or "/callback"
        self.captured: dict = {}
        self._event = threading.Event()
        self._httpd: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # silence stderr
                return

            def do_GET(self):
                p = urlparse(self.path)
                if p.path != outer.path:
                    self.send_response(404)
                    self.end_headers()
                    return
                q = parse_qs(p.query)
                if "url" not in outer.captured:
                    outer.captured["url"] = f"http://{outer.host}:{outer.port}{self.path}"
                    outer.captured["code"] = (q.get("code") or [""])[0]
                    outer.captured["state"] = (q.get("state") or [""])[0]
                    outer.captured["error"] = (q.get("error") or q.get("error_description") or [""])[0]
                    outer._event.set()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<!doctype html><meta charset=utf-8><title>OK</title>"
                    b"<h2 style='font-family:sans-serif'>Authorization captured.</h2>"
                    b"<p style='font-family:sans-serif'>You can close this tab.</p>"
                )

        self._httpd = _ReuseTCPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout=timeout)

    def stop(self) -> None:
        try:
            if self._httpd is not None:
                self._httpd.shutdown()
                self._httpd.server_close()
        except Exception:
            pass


def run(authorize_url: str, email: str, password: str, timeout_s: int = 240,
        bind_local_callback: bool = False, on_browser=None,
        stop_event=None) -> dict:
    parsed = urlparse(authorize_url)
    qs = parse_qs(parsed.query)
    redirect_uri = (qs.get("redirect_uri") or [""])[0]
    redirect = urlparse(redirect_uri)
    cb_host = redirect.hostname or "127.0.0.1"
    cb_port = redirect.port or 80
    cb_path = redirect.path or "/callback"
    log(f"expecting callback at {cb_host}:{cb_port}{cb_path}")

    # In self-mode we own the redirect_uri, so spin up a local server that
    # answers 200 OK and records the code. This is the most reliable capture
    # path; the CDP listener stays armed as a backup.
    server: _CallbackServer | None = None
    if bind_local_callback:
        try:
            server = _CallbackServer(cb_host, cb_port, cb_path)
            server.start()
            log(f"local callback server listening on http://{cb_host}:{cb_port}{cb_path}")
        except Exception as e:
            log(f"could not bind local callback ({e}); relying on CDP listener only")
            server = None

    browser = make_browser()
    if on_browser is not None:
        try:
            on_browser(browser)
        except Exception:
            pass
    captured: dict = {}

    def _stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    def maybe_capture(url_str: str) -> bool:
        if not url_str or "url" in captured:
            return False
        try:
            p = urlparse(url_str)
        except Exception:
            return False
        if (p.hostname in {cb_host, "127.0.0.1", "localhost"}
                and (p.port or 80) == cb_port
                and p.path.startswith(cb_path)):
            q = parse_qs(p.query)
            captured["url"] = url_str
            captured["code"] = (q.get("code") or [""])[0]
            captured["state"] = (q.get("state") or [""])[0]
            captured["error"] = (q.get("error") or q.get("error_description") or [""])[0]
            return True
        return False

    try:
        tabs = browser.get_tabs()
        page = tabs[-1] if tabs else browser.new_tab()

        # Subscribe to CDP request events so we catch the redirect to the
        # callback URL even if the local server isn't listening (Chrome only
        # paints a connection-refused page in that case, but the request was
        # still issued — and that's where the code lives).
        try:
            page.listen.start("/callback", method="GET")
            log("network listener armed on /callback")
        except Exception as e:
            log(f"could not arm listener: {e}")

        log("navigating to authorize URL")
        page.get(authorize_url)
        page.wait.doc_loaded(timeout=10)

        # phase 1: click "log in with email" if shown
        for _ in range(8):
            if _stopped():
                return captured
            try:
                if page.run_js(JS_CLICK_LOGIN_WITH_EMAIL):
                    log("clicked login-with-email")
                    time.sleep(1.0)
                    break
            except Exception:
                pass
            time.sleep(0.5)

        # phase 2: fill email + continue
        deadline = time.time() + 30
        email_done = False
        while time.time() < deadline:
            if _stopped():
                return captured
            try:
                r = page.run_js(JS_FILL_EMAIL_AND_CONTINUE, email)
            except Exception as e:
                r = f"err:{e}"
            log(f"email step → {r}")
            if r == "clicked":
                email_done = True
                break
            if r == "filled-no-button":
                time.sleep(0.6)
                continue
            time.sleep(0.6)
        if not email_done:
            log("email phase did not click a continue button — proceeding anyway")

        # phase 3: fill password (don't submit yet)
        deadline = time.time() + 30
        pw_filled = False
        while time.time() < deadline:
            if _stopped():
                return captured
            try:
                r = page.run_js(JS_FILL_PASSWORD, password)
            except Exception as e:
                r = f"err:{e}"
            log(f"password step → {r}")
            if r == "filled":
                pw_filled = True
                break
            time.sleep(0.6)
        if not pw_filled:
            raise RuntimeError("could not fill password input")

        # phase 4: solve Turnstile
        drive_turnstile(page, log_callback=log, deadline_s=timeout_s // 2,
                         stop_event=stop_event)
        if _stopped():
            return captured

        # phase 5: submit
        for _ in range(20):
            if _stopped():
                return captured
            try:
                r = page.run_js(JS_SUBMIT_PASSWORD)
            except Exception as e:
                r = f"err:{e}"
            log(f"submit step → {r}")
            if r == "clicked":
                break
            time.sleep(0.6)

        # quick post-submit credential check — xAI usually paints
        # "错误的邮箱地址或密码" within ~1.5s of clicking Sign in.
        time.sleep(1.5)
        try:
            err_msg = page.run_js(JS_DETECT_AUTH_ERROR)
        except Exception:
            err_msg = ""
        if err_msg:
            raise AuthCredentialError(str(err_msg)[:120])

        # phase 6: drain the listener (and the local server) and click consent until we capture the callback
        consent_deadline = time.time() + timeout_s
        last_consent_attempt = 0.0
        last_auth_check = 0.0
        while time.time() < consent_deadline:
            if _stopped():
                return captured
            # 0) local server captured it?
            if server is not None and "url" in server.captured:
                captured.update(server.captured)
                break

            # 0.5) periodically check whether the page is showing an
            # "invalid email/password" error — bail fast in that case so
            # the GUI can move on to the next account.
            now = time.time()
            if now - last_auth_check > 1.5:
                last_auth_check = now
                try:
                    err_msg = page.run_js(JS_DETECT_AUTH_ERROR)
                except Exception:
                    err_msg = ""
                if err_msg:
                    raise AuthCredentialError(str(err_msg)[:120])

            # 1) drain any queued /callback events from CDP listener
            try:
                packet = page.listen.wait(timeout=0.4, fit_count=False)
                if packet:
                    pkts = packet if isinstance(packet, list) else [packet]
                    for pk in pkts:
                        try:
                            url_str = pk.url if hasattr(pk, "url") else None
                        except Exception:
                            url_str = None
                        if url_str:
                            log(f"listener saw: {url_str[:160]}")
                            if maybe_capture(url_str):
                                break
            except Exception:
                pass
            if "url" in captured:
                break

            # 2) sometimes the page url itself is enough (Chrome stuck on net::ERR_CONNECTION_REFUSED still exposes the URL)
            try:
                if maybe_capture(page.url or ""):
                    break
            except Exception:
                pass

            # 3) keep clicking the consent button until consent goes away
            now = time.time()
            if now - last_consent_attempt > 0.7:
                last_consent_attempt = now
                try:
                    r = page.run_js(JS_CLICK_CONSENT)
                except Exception:
                    r = None
                if r == "clicked":
                    log("clicked consent")
            time.sleep(0.2)

        if "url" not in captured:
            log("never saw a callback request inside the timeout window")

        return captured
    finally:
        try:
            browser.quit(del_data=False)
        except Exception:
            pass
        if on_browser is not None:
            try:
                on_browser(None)
            except Exception:
                pass
        if server is not None:
            server.stop()


def maybe_forward(captured: dict, template: str, method: str, bearer: str | None) -> None:
    if not template or not captured.get("code"):
        return
    from urllib.parse import quote

    url = (template
           .replace("{code}", quote(captured.get("code") or "", safe=""))
           .replace("{state}", quote(captured.get("state") or "", safe="")))
    headers = {}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    try:
        from curl_cffi import requests as cffi
        log(f"forwarding to {method} {url[:120]}…")
        if method.upper() == "GET":
            resp = cffi.get(url, headers=headers, timeout=30)
        else:
            resp = cffi.post(url, headers=headers, timeout=30, data="")
        log(f"forward status={resp.status_code} body={resp.text[:200]}")
    except Exception as e:
        log(f"forward failed: {e}")


def process_account_self(email: str, password: str, cap_base_url: str,
                          management_key: str, timeout_s: int = 240,
                          out_path: str | None = None,
                          log_callback=None,
                          on_browser=None,
                          stop_event=None,
                          callback_port: int = CALLBACK_PORT) -> dict:
    """Run the full self-mode flow for one account. Returns a result dict:
        {"ok": bool, "email": str, "code": str, "record": dict | None,
         "upload": dict | None, "error": str | None}
    log_callback (optional) receives one-line strings — used by the GUI to
    forward into its log pane. The module-level `log()` continues to print
    to stdout.
    """
    def _log(msg: str) -> None:
        log(msg)
        if log_callback:
            try:
                log_callback(msg)
            except Exception:
                pass

    out = {"ok": False, "email": email, "code": "", "record": None,
           "upload": None, "error": None}

    pkce = make_pkce()
    _log(f"pkce state={pkce['state'][:8]}… nonce={pkce['nonce'][:8]}… port={callback_port}")
    redirect = redirect_uri_for(callback_port)
    authorize_url = build_authorize_url(pkce, redirect_uri=redirect)

    try:
        captured = run(authorize_url, email, password,
                       timeout_s=timeout_s, bind_local_callback=True,
                       on_browser=on_browser, stop_event=stop_event)
    except AuthCredentialError as e:
        out["error"] = f"bad_credentials: {e}"
        return out
    except Exception as e:
        out["error"] = f"login_failed: {e}"
        return out

    if stop_event is not None and stop_event.is_set():
        out["error"] = "stopped"
        return out

    if captured.get("error"):
        out["error"] = f"oauth_error: {captured.get('error')}"
        return out
    if not captured.get("code"):
        out["error"] = "no_code_captured"
        return out
    if captured.get("state") and captured.get("state") != pkce["state"]:
        out["error"] = "state_mismatch"
        return out

    out["code"] = captured["code"]
    try:
        tokens = exchange_code(captured["code"], pkce["verifier"], redirect_uri=redirect)
    except Exception as e:
        out["error"] = f"token_exchange_failed: {e}"
        return out

    try:
        record = build_auth_record(tokens, fallback_email=email, redirect_uri=redirect)
    except Exception as e:
        out["error"] = f"record_build_failed: {e}"
        return out
    out["record"] = record

    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)
        except Exception as e:
            _log(f"could not write {out_path}: {e}")

    try:
        result = upload_auth_file(record, cap_base_url, management_key)
    except Exception as e:
        out["error"] = f"upload_failed: {e}"
        return out
    out["upload"] = result
    out["ok"] = True
    return out


def list_existing_emails(cap_base_url: str, management_key: str) -> set[str]:
    """Return the set of emails CPA already has registered (any provider)."""
    base = cap_base_url.rstrip("/")
    url = f"{base}/v0/management/auth-files"
    headers = {"Authorization": f"Bearer {management_key}"}
    resp = cffi.get(url, headers=headers, timeout=20)
    if resp.status_code >= 400:
        raise RuntimeError(f"list failed {resp.status_code}: {resp.text[:200]}")
    data = resp.json() or {}
    out: set[str] = set()
    for f in data.get("files", []) or []:
        em = (f.get("email") or f.get("account") or "").strip().lower()
        if em:
            out.add(em)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="DrissionPage-based xAI OAuth login → CPA auth-file upload")
    ap.add_argument("--mode", choices=["self", "external"], default="self",
                    help=("self: generate PKCE locally, drive login, exchange code, "
                          "upload xai-{email}.json to CPA. "
                          "external: drive login for an authorize URL whose verifier "
                          "lives on CPA — only capture the callback URL."))
    ap.add_argument("--authorize-url", default="",
                    help="external mode only: the authorize URL CPA gave you")
    ap.add_argument("--email", default=DEFAULT_EMAIL)
    ap.add_argument("--password", default=DEFAULT_PASSWORD)
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--cap-base-url", default=DEFAULT_CAP_BASE,
                    help="self mode: CPA base URL for the auth-file upload")
    ap.add_argument("--management-key", default=DEFAULT_MGMT_KEY,
                    help="self mode: CPA management bearer key")
    ap.add_argument("--out", default="",
                    help="self mode: also write the auth record JSON here for inspection")
    args = ap.parse_args()

    if args.mode == "external":
        if not args.authorize_url:
            log("external mode requires --authorize-url")
            return 2
        captured = run(args.authorize_url, args.email, args.password,
                       timeout_s=args.timeout, bind_local_callback=False)
        log("CAPTURED:")
        log(f"  url   = {captured.get('url')}")
        log(f"  code  = {captured.get('code')}")
        log(f"  state = {captured.get('state')}")
        log(f"  error = {captured.get('error')}")
        if captured.get("error"):
            return 1
        return 0 if captured.get("code") else 1

    # ---- self mode ----
    pkce = make_pkce()
    log(f"pkce state={pkce['state'][:8]}… nonce={pkce['nonce'][:8]}…")
    authorize_url = build_authorize_url(pkce)
    log(f"authorize_url = {authorize_url[:120]}…")

    captured = run(authorize_url, args.email, args.password,
                   timeout_s=args.timeout, bind_local_callback=True)
    log("CAPTURED:")
    log(f"  url   = {captured.get('url')}")
    log(f"  code  = {captured.get('code')}")
    log(f"  state = {captured.get('state')}")
    log(f"  error = {captured.get('error')}")

    if captured.get("error"):
        log(f"OAuth error: {captured.get('error')}")
        return 1
    if not captured.get("code"):
        log("no code captured — abort")
        return 1
    if captured.get("state") and captured.get("state") != pkce["state"]:
        log(f"state mismatch: expected {pkce['state']} got {captured.get('state')}")
        return 1

    log("exchanging code → tokens")
    tokens = exchange_code(captured["code"], pkce["verifier"])
    log(f"tokens: keys={sorted(tokens.keys())} expires_in={tokens.get('expires_in')}")

    record = build_auth_record(tokens, fallback_email=args.email)
    log(f"record built for email={record['email']} sub={record['sub']}")

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)
            log(f"wrote local copy to {args.out}")
        except Exception as e:
            log(f"could not write --out: {e}")

    log(f"uploading to {args.cap_base_url}/v0/management/auth-files")
    result = upload_auth_file(record, args.cap_base_url, args.management_key)
    log(f"upload OK: file_name={result['file_name']} status={result['status']}")
    log(f"upload body: {result['body']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
