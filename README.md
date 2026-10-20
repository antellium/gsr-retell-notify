# GSR Retell Notify + Callback Bridge
Retell webhook -> spam filter -> SMS Anthony -> ring Anthony's cell until every real lead is handled.

On the ring: 1 = call them now, 2 = already handled, 3 = block as spam, 4 = skip for now.
Unhandled leads ring again every 90 min, 8 AM-9 PM Central, for up to 72 hours.

Render env vars: RETELL_API_KEY, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER,
ANTHONY_CELL_PHONE, PUBLIC_URL, ADMIN_TOKEN, STATE_DIR (persistent disk mount, /data).

Admin: GET /admin/queue and POST /admin/test {"number": "+1..."} with header X-Admin-Token.
