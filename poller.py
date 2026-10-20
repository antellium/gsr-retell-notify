#!/usr/bin/env python3
"""
GSR Retell webhook receiver + Callingly-style callback bridge.

1. Retell POSTs call events to /. We re-fetch the call from the Retell API
   (so a forged webhook can't inject anything), filter spam, SMS Anthony.
2. Real leads go in a callback queue. Twilio rings Anthony's cell, reads each
   waiting lead, and he presses:
     1 = call them now (dials the lead from the line they called)
     2 = already handled
     3 = block as spam
     4 = skip for now
   Anything not handled rings again every 90 minutes, 8 AM to 9 PM Central,
   for up to 72 hours.

ENV required:
  RETELL_API_KEY, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER,
  ANTHONY_CELL_PHONE, PUBLIC_URL (https://gsr-retell-notify.onrender.com),
  ADMIN_TOKEN, STATE_DIR (persistent disk mount, e.g. /data)
  PORT (Render auto-sets)
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

TZ = ZoneInfo("America/Chicago")
RING_HOURS = (8, 21)  # local time, protects 10PM bedtime
RETRY_SECS = 90 * 60
MAX_AGE_SECS = 72 * 3600
SESSION_MAX_SECS = 30 * 60

VENDOR_KEYWORDS = [
    "merchant service", "advertising opportunity", "marketing team",
    "lead qualification system", "ai receptionist", "front desk",
    "wellness kiosk", "vouchers on in-store", "vendor opportunity",
    "saas", "pitch", "google business", "seo services",
    "credit card processing", "payment processing",
]

# Robocall fingerprints. Spammers rotate spoofed numbers (508-206-xxxx, 252-201-xxxx,
# 430-200-xxxx...), so match on what they say, not who they are.
ROBOCALL_PATTERNS = [
    "listing verification", "google voice search", "business is not verified",
    "robocall", "automated message", "automated system", "pre-recorded",
    "likely spam", "likely a scam", "phishing", "press a number",
    "health and human services",
]

# Real calls that get a text but no ring: vendors, wrong numbers, tenant repairs.
NO_RING_PATTERNS = [
    "to offer", "offering", "offer services", "services to", "vendor",
    "account manager", "by mistake", "wrong number", "union", "advertis",
    "marketing", "bookkeeping", "internet service", "is no ", "car detailing",
    "maintenance", "repair request", "unit repair", "work request", "air conditioning",
    "ac issue", "ac problem", "hot water", "no water", "water pressure", "water heater",
]

NO_INTENT_PATTERNS = [
    "hung up shortly after", "hung up before", "hung up immediately",
    "did not respond to the agent", "no conversation took place",
    "no response from the caller", "no further interaction",
    "no information was exchanged", "disconnected before",
    "did not provide", "inaudible",
]

SEED_BLOCKLIST = Path(__file__).parent / "blocked_numbers.txt"
STATE_PATH = Path(os.environ.get("STATE_DIR", "/tmp")) / "callback_state.json"

LOCK = threading.RLock()
SESSIONS = {}  # session id -> {"queue": [numbers], "call_sid": str, "started": ts}


def digits10(n):
    return "".join(ch for ch in (n or "") if ch.isdigit())[-10:]


# ---------- state ----------

def load_state():
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"leads": {}, "closed": [], "blocked": [], "seen_calls": []}


def save_state(state):
    state["seen_calls"] = state["seen_calls"][-1000:]
    state["closed"] = state["closed"][-500:]
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    tmp.replace(STATE_PATH)


def blocklist(state):
    seed = set()
    if SEED_BLOCKLIST.exists():
        seed = {digits10(l) for l in SEED_BLOCKLIST.read_text().splitlines()
                if l.strip() and not l.startswith("#")}
    return seed | set(state["blocked"])


def close_lead(state, number, status):
    lead = state["leads"].pop(number, None)
    if lead:
        lead["status"] = status
        lead["closed_ts"] = int(time.time())
        state["closed"].append(lead)
    return lead


# ---------- filters ----------

def is_real_call(call, blocked=frozenset()):
    disc = call.get("disconnection_reason", "")
    dur = 0
    if call.get("end_timestamp") and call.get("start_timestamp"):
        dur = round((call["end_timestamp"] - call["start_timestamp"]) / 1000)
    analysis = call.get("call_analysis") or {}
    summary = (analysis.get("call_summary") or "").lower()
    frm = digits10(call.get("from_number"))
    if frm and frm in blocked:
        return False, "blocklist"
    text = summary + " " + (call.get("transcript") or "").lower()
    for pat in ROBOCALL_PATTERNS:
        if pat in text:
            return False, f"robocall:{pat}"
    if disc == "no_valid_payment":
        return False, "billing_fail"
    if disc == "inactivity":
        return False, "inactivity"
    if dur < 20:
        return False, "too_short"
    if not summary:
        return False, "no_summary"
    for pat in NO_INTENT_PATTERNS:
        if pat in summary:
            return False, "no_intent"
    for kw in VENDOR_KEYWORDS:
        if kw in summary:
            return False, "vendor"
    return True, "real"


def wants_ring(call):
    frm = call.get("from_number") or ""
    if not frm.startswith("+") or len(frm) < 11:
        return False, "no_callback_number"
    summary = ((call.get("call_analysis") or {}).get("call_summary") or "").lower()
    for pat in NO_RING_PATTERNS:
        if pat in summary:
            return False, f"no_ring:{pat.strip()}"
    return True, "ring"


def build_whisper(call):
    summary = ((call.get("call_analysis") or {}).get("call_summary") or "").strip()
    first = summary.split(". ")[0].rstrip(".")
    first = first.replace("Golden Spiral Realty", "us").replace("The agent", "the receptionist")
    return (first[:220] + ".") if first else "A caller left a message."


def in_ring_hours(ts=None):
    hour = datetime.fromtimestamp(ts or time.time(), TZ).hour
    return RING_HOURS[0] <= hour < RING_HOURS[1]


# ---------- outbound APIs ----------

def _twilio_post(url, fields):
    sid = os.environ["TWILIO_ACCOUNT_SID"]
    auth = os.environ["TWILIO_AUTH_TOKEN"]
    token = base64.b64encode(f"{sid}:{auth}".encode()).decode()
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST",
        headers={"Authorization": f"Basic {token}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, json.loads(r.read())


def send_sms(body):
    sid = os.environ["TWILIO_ACCOUNT_SID"]
    status, _ = _twilio_post(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json", {
        "From": os.environ.get("TWILIO_FROM_NUMBER", "+18328003644"),
        "To": os.environ["ANTHONY_CELL_PHONE"], "Body": body})
    return status


def ring_anthony(session_id):
    sid = os.environ["TWILIO_ACCOUNT_SID"]
    base = os.environ["PUBLIC_URL"].rstrip("/")
    _, call = _twilio_post(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json", {
        "To": os.environ["ANTHONY_CELL_PHONE"],
        "From": os.environ.get("TWILIO_FROM_NUMBER", "+18328003644"),
        "Url": f"{base}/voice/start?s={session_id}",
        "StatusCallback": f"{base}/voice/status?s={session_id}",
        "MachineDetection": "Enable",
        "Timeout": "25",
    })
    return call["sid"]


def retell_get_call(call_id):
    req = urllib.request.Request(
        f"https://api.retellai.com/v2/get-call/{urllib.parse.quote(call_id)}",
        headers={"Authorization": f"Bearer {os.environ['RETELL_API_KEY']}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def format_sms(call):
    frm = call.get("from_number", "Anonymous")
    to = call.get("to_number", "")
    dur = 0
    if call.get("end_timestamp") and call.get("start_timestamp"):
        dur = round((call["end_timestamp"] - call["start_timestamp"]) / 1000)
    analysis = call.get("call_analysis") or {}
    summary = (analysis.get("call_summary") or "").strip()
    sentiment = analysis.get("user_sentiment", "")
    line_to = {"4653": "844", "7800": "LSA"}.get(to[-4:], "832")
    head = f"Call {line_to} from {frm} ({dur}s)"
    if sentiment and sentiment not in ("Unknown", "Neutral"):
        head += f" {sentiment}"
    if summary:
        head += f"\n{summary[:340]}"
    return head[:1500]


# ---------- call intake ----------

def process_call(call):
    """Handle one finished Retell call. Returns a short result string for logs."""
    cid = call.get("call_id", "?")
    with LOCK:
        state = load_state()
        if cid in state["seen_calls"]:
            return "dupe"
        state["seen_calls"].append(cid)
        save_state(state)
        real, reason = is_real_call(call, blocklist(state))
    if not real:
        return f"skip {reason}"

    try:
        print(f"sms cid={cid} http={send_sms(format_sms(call))}", flush=True)
    except Exception as e:
        print(f"sms_err cid={cid} {e}", file=sys.stderr, flush=True)

    ring, why = wants_ring(call)
    if not ring:
        return f"sms_only {why}"
    enqueue(call["from_number"], call.get("to_number"), build_whisper(call), cid)
    return "queued"


def enqueue(number, line, whisper, call_id):
    now = int(time.time())
    with LOCK:
        state = load_state()
        lead = state["leads"].get(number)
        if lead:
            lead["calls"] += 1
            lead["whisper"] = whisper
            lead["last_call_ts"] = time.time()
            lead["call_ids"].append(call_id)
        else:
            lead = state["leads"][number] = {
                "number": number, "line": line or os.environ.get("TWILIO_FROM_NUMBER", "+18328003644"),
                "whisper": whisper, "calls": 1, "first_call_ts": now, "last_call_ts": time.time(),
                "rings": 0, "call_ids": [call_id], "status": "pending",
            }
        lead["next_ring_ts"] = now  # fresh call: ring right away (within hours)
        save_state(state)


# ---------- scheduler ----------

def tick(now=None):
    """Expire old leads, start a ring session if anything is due. Returns session id or None."""
    now = now or time.time()
    with LOCK:
        for s_id, s in list(SESSIONS.items()):
            if now - s["started"] > SESSION_MAX_SECS:
                SESSIONS.pop(s_id)
        state = load_state()
        for num, lead in list(state["leads"].items()):
            if now - lead["first_call_ts"] > MAX_AGE_SECS:
                close_lead(state, num, "expired")
                try:
                    send_sms(f"Stopped ringing you about {num} after 72 hours. {lead['whisper']}")
                except Exception as e:
                    print(f"sms_err expire {num} {e}", file=sys.stderr, flush=True)
        save_state(state)
        if SESSIONS or not in_ring_hours(now):
            return None
        if not any(l["next_ring_ts"] <= now for l in state["leads"].values()):
            return None
        # Anthony is picking up anyway, so walk him through everything waiting. Newest first.
        queue = [l["number"] for l in sorted(state["leads"].values(), key=lambda l: -l["last_call_ts"])]
        for num in queue:
            state["leads"][num]["next_ring_ts"] = int(now + RETRY_SECS)
            state["leads"][num]["rings"] += 1
        save_state(state)
        s_id = secrets.token_hex(8)
        SESSIONS[s_id] = {"queue": queue, "call_sid": None, "started": now}
    try:
        call_sid = ring_anthony(s_id)
        with LOCK:
            if s_id in SESSIONS:
                SESSIONS[s_id]["call_sid"] = call_sid
        print(f"ring session={s_id} leads={len(queue)} call={call_sid}", flush=True)
    except Exception as e:
        print(f"ring_err {e}", file=sys.stderr, flush=True)
        with LOCK:
            SESSIONS.pop(s_id, None)
    return s_id


def scheduler_loop():
    while True:
        try:
            tick()
        except Exception as e:
            print(f"tick_err {e}", file=sys.stderr, flush=True)
        time.sleep(30)


# ---------- TwiML ----------

def say(text):
    return f'<Say voice="Polly.Matthew-Neural">{escape(text)}</Say>'


def twiml(*parts):
    return '<?xml version="1.0" encoding="UTF-8"?><Response>' + "".join(parts) + "</Response>"


def url(path, **q):
    return escape(f"{os.environ['PUBLIC_URL'].rstrip('/')}{path}?{urllib.parse.urlencode(q)}")


def ago(ts):
    mins = int((time.time() - ts) / 60)
    if mins < 2:
        return "just now"
    if mins < 60:
        return f"{mins} minutes ago"
    hours = mins // 60
    return f"{hours} hour{'s' if hours > 1 else ''} ago"


def voice_lead(s_id, i, retry):
    """Read lead #i of the session, or move past leads already closed."""
    with LOCK:
        sess = SESSIONS.get(s_id)
        state = load_state()
        queue = sess["queue"] if sess else []
        while i < len(queue) and queue[i] not in state["leads"]:
            i += 1
        if i >= len(queue):
            return twiml(say("That's everything. Talk soon."), "<Hangup/>")
        lead = state["leads"][queue[i]]
    times = "Called" if lead["calls"] == 1 else f"Called {lead['calls']} times, first"
    prompt = (f"{lead['whisper']} {times} {ago(lead['first_call_ts'])}. "
              "Press 1 to call them now. 2 if you already handled it. 3 to block as spam. 4 to skip for now.")
    if retry >= 2:
        return twiml(say("No problem. I'll call you again in 90 minutes."), "<Hangup/>")
    return twiml(
        f'<Gather numDigits="1" timeout="6" action="{url("/voice/key", s=s_id, i=i)}">{say(prompt)}</Gather>',
        f'<Redirect>{url("/voice/lead", s=s_id, i=i, r=retry + 1)}</Redirect>')


def voice_key(s_id, i, digit):
    with LOCK:
        sess = SESSIONS.get(s_id)
        if not sess or i >= len(sess["queue"]):
            return twiml("<Hangup/>")
        number = sess["queue"][i]
        state = load_state()
        lead = state["leads"].get(number)
        if not lead:
            return twiml(f'<Redirect>{url("/voice/lead", s=s_id, i=i + 1, r=0)}</Redirect>')
        nxt = f'<Redirect>{url("/voice/lead", s=s_id, i=i + 1, r=0)}</Redirect>'
        if digit == "1":
            return twiml(say("Connecting."),
                f'<Dial callerId="{escape(lead["line"])}" timeout="30" '
                f'action="{url("/voice/dialed", s=s_id, i=i)}"><Number>{escape(number)}</Number></Dial>')
        if digit == "2":
            close_lead(state, number, "handled")
            save_state(state)
            return twiml(say("Got it."), nxt)
        if digit == "3":
            state["blocked"].append(digits10(number))
            close_lead(state, number, "blocked")
            save_state(state)
            return twiml(say("Blocked. They won't ring you again."), nxt)
        if digit == "4":
            return twiml(say("Okay. Later."), nxt)
    return twiml(f'<Redirect>{url("/voice/lead", s=s_id, i=i, r=0)}</Redirect>')


def voice_dialed(s_id, i, dial_status):
    with LOCK:
        sess = SESSIONS.get(s_id)
        number = sess["queue"][i] if sess and i < len(sess["queue"]) else None
        if number and dial_status == "completed":
            state = load_state()
            close_lead(state, number, "connected")
            save_state(state)
            msg = "Next one."
        else:
            msg = "They didn't pick up. I'll remind you again in 90 minutes."
    return twiml(say(msg), f'<Redirect>{url("/voice/lead", s=s_id, i=i + 1, r=0)}</Redirect>')


def twilio_signature_ok(full_url, params, signature):
    data = full_url + "".join(k + params[k] for k in sorted(params))
    digest = hmac.new(os.environ["TWILIO_AUTH_TOKEN"].encode(), data.encode(), hashlib.sha1).digest()
    return hmac.compare_digest(base64.b64encode(digest).decode(), signature or "")


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(fmt % args, file=sys.stderr, flush=True)

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def _admin_ok(self):
        tok = os.environ.get("ADMIN_TOKEN")
        return bool(tok) and hmac.compare_digest(self.headers.get("X-Admin-Token", ""), tok)

    def do_GET(self):
        if self.path.startswith("/admin/queue"):
            if not self._admin_ok():
                return self._send(403, {"error": "forbidden"})
            with LOCK:
                state = load_state()
                return self._send(200, {"leads": list(state["leads"].values()),
                                        "closed": state["closed"][-20:],
                                        "blocked": state["blocked"],
                                        "sessions": len(SESSIONS)})
        self._send(200, "gsr-retell-notify alive", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        parsed = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        if parsed.path.startswith("/voice/"):
            params = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode(), keep_blank_values=True).items()}
            full_url = os.environ["PUBLIC_URL"].rstrip("/") + self.path
            if not twilio_signature_ok(full_url, params, self.headers.get("X-Twilio-Signature")):
                print(f"bad twilio signature {parsed.path}", file=sys.stderr, flush=True)
                return self._send(403, {"error": "bad signature"})
            return self._voice(parsed.path, q, params)

        if parsed.path == "/admin/test":
            if not self._admin_ok():
                return self._send(403, {"error": "forbidden"})
            body = json.loads(raw or b"{}")
            enqueue(body["number"], body.get("line"), body.get("whisper", "This is a test callback."), "test")
            return self._send(200, {"queued": body["number"], "session": tick()})

        return self._retell(raw)

    def _voice(self, path, q, params):
        s_id = q.get("s", "")
        i = int(q.get("i", "0"))
        if path == "/voice/start":
            if params.get("AnsweredBy", "").startswith(("machine", "fax")):
                return self._send(200, twiml("<Hangup/>"), "text/xml")
            with LOCK:
                n = len(SESSIONS.get(s_id, {}).get("queue", []))
            intro = say(f"Golden Spiral callbacks. You have {n} waiting." if n != 1
                        else "Golden Spiral callback. One person waiting.")
            body = voice_lead(s_id, 0, 0).replace("<Response>", "<Response>" + intro, 1)
        elif path == "/voice/lead":
            body = voice_lead(s_id, i, int(q.get("r", "0")))
        elif path == "/voice/key":
            body = voice_key(s_id, i, params.get("Digits", ""))
        elif path == "/voice/dialed":
            body = voice_dialed(s_id, i, params.get("DialCallStatus", ""))
        elif path == "/voice/status":
            print(f"session={s_id} ended status={params.get('CallStatus')}", flush=True)
            with LOCK:
                SESSIONS.pop(s_id, None)
            body = twiml()
        else:
            return self._send(404, {"error": "not found"})
        self._send(200, body, "text/xml")

    def _retell(self, raw):
        try:
            payload = json.loads(raw or b"{}")
        except Exception:
            payload = {}
        event = payload.get("event") or payload.get("type") or ""
        cid = (payload.get("call") or {}).get("call_id")
        if event != "call_analyzed" or not cid:
            return self._send(200, {"ignored": event})
        try:
            call = retell_get_call(cid)  # trust Retell's API, not the webhook body
        except Exception as e:
            print(f"retell_fetch_err cid={cid} {e}", file=sys.stderr, flush=True)
            return self._send(500, {"error": "fetch failed"})
        if call.get("direction") != "inbound":
            return self._send(200, {"skipped": "not_inbound"})
        result = process_call(call)
        print(f"call cid={cid} {result}", flush=True)
        self._send(200, {"result": result})


def main():
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=scheduler_loop, daemon=True).start()
    port = int(os.environ.get("PORT", "8000"))
    print(f"listening on :{port} state={STATE_PATH}", flush=True)
    ThreadingHTTPServer(("", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
