#!/usr/bin/env python3
"""
GSR Retell webhook receiver.
Retell POSTs every call_analyzed event to this service.
Filter for real calls, SMS Anthony via Twilio.

ENV required:
  TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER, ANTHONY_CELL_PHONE
  PORT (Render auto-sets)
"""
import base64
import json
import os
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

VENDOR_KEYWORDS = [
    "merchant service", "advertising opportunity", "marketing team",
    "lead qualification system", "ai receptionist", "front desk",
    "wellness kiosk", "vouchers on in-store", "vendor opportunity",
    "saas", "pitch", "google business", "seo services",
    "credit card processing", "payment processing",
]

NO_INTENT_PATTERNS = [
    "hung up shortly after", "hung up before", "hung up immediately",
    "did not respond to the agent", "no conversation took place",
    "no response from the caller", "no further interaction",
    "no information was exchanged", "disconnected before",
    "did not provide", "inaudible",
]


def is_real_call(call):
    disc = call.get("disconnection_reason", "")
    dur = 0
    if call.get("end_timestamp") and call.get("start_timestamp"):
        dur = round((call["end_timestamp"] - call["start_timestamp"]) / 1000)
    analysis = call.get("call_analysis") or {}
    summary = (analysis.get("call_summary") or "").lower()
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


def format_sms(call):
    frm = call.get("from_number", "Anonymous")
    to = call.get("to_number", "")
    dur = 0
    if call.get("end_timestamp") and call.get("start_timestamp"):
        dur = round((call["end_timestamp"] - call["start_timestamp"]) / 1000)
    analysis = call.get("call_analysis") or {}
    summary = (analysis.get("call_summary") or "").strip()
    sentiment = analysis.get("user_sentiment", "")
    line_to = "844" if to.endswith("4653") else "832"
    head = f"Call {line_to} from {frm} ({dur}s)"
    if sentiment and sentiment not in ("Unknown", "Neutral"):
        head += f" {sentiment}"
    if summary:
        head += f"\n{summary[:340]}"
    return head[:1500]


def send_sms(body):
    sid = os.environ["TWILIO_ACCOUNT_SID"]
    auth = os.environ["TWILIO_AUTH_TOKEN"]
    from_n = os.environ.get("TWILIO_FROM_NUMBER", "+18328003644")
    to_n = os.environ["ANTHONY_CELL_PHONE"]
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    data = urllib.parse.urlencode({"From": from_n, "To": to_n, "Body": body}).encode()
    token = base64.b64encode(f"{sid}:{auth}".encode()).decode()
    req = urllib.request.Request(url, data=data, method="POST",
        headers={"Authorization": f"Basic {token}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(fmt % args, file=sys.stderr)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"gsr-retell-notify alive")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {}
        event = payload.get("event") or payload.get("type") or ""
        call = payload.get("call") or payload
        cid = call.get("call_id", "?")

        if event not in ("call_analyzed", "call_ended"):
            print(f"ignore event={event} cid={cid}")
            return self._ok({"ignored": True})

        if event == "call_ended" and not (call.get("call_analysis") or {}).get("call_summary"):
            print(f"defer cid={cid} waiting_for_call_analyzed")
            return self._ok({"deferred": True})

        if call.get("direction") and call["direction"] != "inbound":
            return self._ok({"skipped": "not_inbound"})

        real, reason = is_real_call(call)
        if not real:
            print(f"skip cid={cid} reason={reason}")
            return self._ok({"skipped": reason})

        try:
            status = send_sms(format_sms(call))
            print(f"sms cid={cid} http={status}")
            return self._ok({"sms": status})
        except Exception as e:
            print(f"sms_err cid={cid} {e}", file=sys.stderr)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def _ok(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


def main():
    port = int(os.environ.get("PORT", "8000"))
    print(f"listening on :{port}", flush=True)
    HTTPServer(("", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
