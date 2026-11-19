import hashlib
import hmac
import json
import os
import sqlite3
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_PATH = "/root/gshop-demo/gshop.db"
CERT_DIR = "/root/gshop-demo/certs"

AES_KEY = hashlib.sha256(b"gshop-demo-aes-256-secret-key").digest()
WEBHOOK_SECRET = b"gshop-payment-gateway-hmac-secret-key"
REPLAY_WINDOW_SECONDS = 300

HTML_PAGE = """<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>G-Shop - Demo Bảo Vệ Giao Dịch Thanh Toán Trực Tuyến</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f4f6f9; margin: 0; padding: 20px; color: #222; }
    .container { max-width: 1100px; margin: auto; }
    h1 { color: #0f4c81; margin-bottom: 5px; }
    .badge { display: inline-block; background: #198754; color: #fff; padding: 4px 10px; border-radius: 4px; font-size: 13px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
    .card { background: #fff; padding: 18px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
    h2 { margin-top: 0; font-size: 18px; color: #0f4c81; border-bottom: 1px solid #eee; padding-bottom: 8px; }
    label { display: block; margin-top: 10px; font-weight: bold; font-size: 13px; }
    input, select { width: 100%; padding: 8px; margin-top: 4px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    button { margin-top: 14px; padding: 10px 14px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
    .btn-primary { background: #0f4c81; color: #fff; }
    .btn-success { background: #198754; color: #fff; }
    .btn-danger { background: #dc3545; color: #fff; }
    .btn-warn { background: #fd7e14; color: #fff; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; word-break: break-all; }
    th { background: #eef3f8; }
    .status-PAID { color: #198754; font-weight: bold; }
    .status-PENDING { color: #d97706; font-weight: bold; }
    pre { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
  </style>
</head>
<body>
<div class="container">
  <h1>G-SHOP — DEMO BẢO VỆ GIAO DỊCH THANH TOÁN TRỰC TUYẾN</h1>
  <span class="badge">HTTPS / TLS 1.2+ Đã Kích Hoạt</span>
  <span class="badge" style="background:#0d6efd;">AES-256-GCM</span>
  <span class="badge" style="background:#6f42c1;">HMAC-SHA256 & Anti-Replay</span>

  <div class="grid">
    <div class="card">
      <h2>1. Tạo đơn hàng mới (Khách hàng trên G-Shop)</h2>
      <label>Mã đơn hàng (Order ID)</label>
      <input id="newOrderId" value="ORD-1003" />
      <label>Tên khách hàng</label>
      <input id="newCustomer" value="Phan Phúc An" />
      <label>Số tiền (VND)</label>
      <input id="newAmount" type="number" value="1500000" />
      <button class="btn-primary" onclick="createOrder()">Đặt hàng (Tạo đơn PENDING)</button>
    </div>

    <div class="card">
      <h2>2. Cổng thanh toán gửi Webhook về G-Shop</h2>
      <label>Chọn đơn hàng thanh toán</label>
      <input id="payOrderId" value="ORD-1003" />
      <label>Số tiền gửi trong Webhook (VND)</label>
      <input id="payAmount" type="number" value="1500000" />
      <label>Mã giao dịch (Transaction ID / Idempotency Key)</label>
      <input id="payTxId" />
      <div>
        <button class="btn-success" onclick="sendWebhook('valid')">Thanh toán hợp lệ (HMAC đúng)</button>
        <button class="btn-danger" onclick="sendWebhook('fake_hmac')">Giả mạo Webhook (Sai HMAC)</button>
        <button class="btn-warn" onclick="sendWebhook('tamper_amount')">Sửa số tiền thành 1.000đ</button>
        <button class="btn-primary" onclick="sendWebhook('replay')">Gửi lại (Test Replay)</button>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:20px;">
    <h2>3. Kết quả phản hồi từ Server G-Shop</h2>
    <pre id="output">Sẵn sàng kiểm thử...</pre>
  </div>

  <div class="card" style="margin-top:20px;">
    <h2>4. Danh sách đơn hàng trong SQLite</h2>
    <table>
      <thead><tr><th>Order ID</th><th>Khách hàng</th><th>Số tiền</th><th>Tiền tệ</th><th>Trạng thái</th></tr></thead>
      <tbody id="ordersBody"></tbody>
    </table>
  </div>

  <div class="card" style="margin-top:20px;">
    <h2>5. Nhật ký giao dịch đã mã hóa AES-256-GCM trong SQLite</h2>
    <table>
      <thead><tr><th>Tx ID</th><th>Order ID</th><th>Hợp lệ</th><th>Lý do</th><th>Dữ liệu mã hóa (AES-256-GCM)</th></tr></thead>
      <tbody id="txBody"></tbody>
    </table>
  </div>
</div>

<script>
  function genTxId() {
    document.getElementById('payTxId').value = 'TX-' + Math.floor(Date.now() / 1000);
  }
  genTxId();

  async function createOrder() {
    const body = {
      order_id: document.getElementById('newOrderId').value,
      customer_name: document.getElementById('newCustomer').value,
      amount: parseInt(document.getElementById('newAmount').value, 10),
      currency: 'VND'
    };
    const res = await fetch('/orders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    document.getElementById('output').textContent = JSON.stringify({ status: res.status, data }, null, 2);
    document.getElementById('payOrderId').value = body.order_id;
    document.getElementById('payAmount').value = body.amount;
    genTxId();
    loadTables();
  }

  async function sendWebhook(mode) {
    if (mode !== 'replay') {
      // Giữ nguyên tx_id khi test replay, các mode khác dùng tx_id hiện tại
    }
    const body = {
      mode: mode,
      tx_id: document.getElementById('payTxId').value,
      order_id: document.getElementById('payOrderId').value,
      amount: mode === 'tamper_amount' ? 1000 : parseInt(document.getElementById('payAmount').value, 10),
      currency: 'VND',
      status: 'SUCCESS'
    };
    const res = await fetch('/simulate-gateway', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    document.getElementById('output').textContent = JSON.stringify(data, null, 2);
    loadTables();
  }

  async function loadTables() {
    const ordersRes = await (await fetch('/orders')).json();
    document.getElementById('ordersBody').innerHTML = ordersRes.orders.map(o => `
      <tr>
        <td>${o.order_id}</td>
        <td>${o.customer_name}</td>
        <td>${o.amount.toLocaleString()}</td>
        <td>${o.currency}</td>
        <td class="status-${o.status}">${o.status}</td>
      </tr>
    `).join('');

    const txRes = await (await fetch('/transactions')).json();
    document.getElementById('txBody').innerHTML = txRes.transactions.map(t => `
      <tr>
        <td>${t.tx_id}</td>
        <td>${t.order_id}</td>
        <td>${t.verified ? '1 (Hợp lệ)' : '0 (Từ chối)'}</td>
        <td>${t.reason}</td>
        <td><code>${t.encrypted_payload}</code></td>
      </tr>
    `).join('');
  }

  loadTables();
</script>
</body>
</html>
"""


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            order_id TEXT PRIMARY KEY,
            customer_name TEXT NOT NULL,
            amount INTEGER NOT NULL,
            currency TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id TEXT PRIMARY KEY,
            order_id TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            verified INTEGER NOT NULL,
            reason TEXT,
            created_at INTEGER NOT NULL
        )
    """)
    sample_orders = [
        ("ORD-1001", "Phan Phuc An", 2500000, "VND", "PENDING", int(time.time())),
        ("ORD-1002", "Nguyen Van A", 1200000, "VND", "PENDING", int(time.time())),
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO orders VALUES (?, ?, ?, ?, ?, ?)",
        sample_orders,
    )
    conn.commit()
    conn.close()


def encrypt_aes_gcm(plaintext_dict: dict) -> str:
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    data = json.dumps(plaintext_dict, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return json.dumps({
        "alg": "AES-256-GCM",
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    })


def compute_hmac(raw_body: bytes, secret: bytes = WEBHOOK_SECRET) -> str:
    return hmac.new(secret, raw_body, hashlib.sha256).hexdigest()


def process_webhook_logic(raw_body: bytes, received_sig: str):
    expected_sig = compute_hmac(raw_body)
    if not received_sig or not hmac.compare_digest(received_sig, expected_sig):
        return 401, {"status": "REJECTED", "reason": "Chữ ký HMAC-SHA256 không hợp lệ"}

    try:
        payload = json.loads(raw_body.decode("utf-8"))
        tx_id = str(payload["tx_id"]).strip()
        order_id = str(payload["order_id"]).strip()
        amount = int(payload["amount"])
        currency = str(payload.get("currency", "VND")).strip()
        status = str(payload["status"]).strip()
        timestamp = int(payload["timestamp"])
    except Exception as e:
        return 400, {"status": "REJECTED", "reason": f"Payload sai định dạng: {e}"}

    now = int(time.time())
    if abs(now - timestamp) > REPLAY_WINDOW_SECONDS:
        return 400, {"status": "REJECTED", "reason": "Timestamp ngoài phạm vi cho phép (nghi vấn Replay)"}

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    existing_tx = cur.execute("SELECT * FROM transactions WHERE tx_id = ?", (tx_id,)).fetchone()
    if existing_tx:
        conn.close()
        return 409, {"status": "REJECTED", "reason": "Giao dịch trùng lặp (tx_id đã xử lý)"}

    order = cur.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,)).fetchone()
    if not order:
        conn.close()
        return 404, {"status": "REJECTED", "reason": "Không tìm thấy mã đơn hàng"}

    if order["status"] == "PAID":
        conn.close()
        return 409, {"status": "REJECTED", "reason": "Đơn hàng đã thanh toán trước đó"}

    if int(order["amount"]) != amount or order["currency"] != currency:
        enc_fail = encrypt_aes_gcm({
            "tx_id": tx_id,
            "order_id": order_id,
            "paid_amount": amount,
            "expected_amount": order["amount"],
            "status": status,
        })
        cur.execute(
            "INSERT INTO transactions VALUES (?, ?, ?, 0, ?, ?)",
            (tx_id, order_id, enc_fail, "Số tiền hoặc loại tiền tệ không khớp đơn hàng", now),
        )
        conn.commit()
        conn.close()
        return 400, {"status": "REJECTED", "reason": "Số tiền hoặc tiền tệ không khớp với đơn hàng"}

    if status != "SUCCESS":
        conn.close()
        return 400, {"status": "REJECTED", "reason": f"Trạng thái giao dịch không thành công: {status}"}

    encrypted_data = encrypt_aes_gcm({
        "tx_id": tx_id,
        "order_id": order_id,
        "amount": amount,
        "currency": currency,
        "status": status,
        "verified_at": now,
    })
    cur.execute(
        "INSERT INTO transactions VALUES (?, ?, ?, 1, 'OK', ?)",
        (tx_id, order_id, encrypted_data, now),
    )
    cur.execute("UPDATE orders SET status = 'PAID' WHERE order_id = ?", (order_id,))
    conn.commit()
    conn.close()

    return 200, {
        "status": "ACCEPTED",
        "message": "Xác thực thành công, đã mã hóa AES-256-GCM và cập nhật đơn hàng PAID",
        "order_id": order_id,
        "tx_id": tx_id,
    }


class GShopHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(HTML_PAGE)
            return

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        if parsed.path == "/orders":
            rows = [dict(r) for r in cur.execute("SELECT * FROM orders").fetchall()]
            conn.close()
            self._send_json(200, {"orders": rows})
            return

        if parsed.path == "/transactions":
            rows = [dict(r) for r in cur.execute("SELECT * FROM transactions").fetchall()]
            conn.close()
            self._send_json(200, {"transactions": rows})
            return

        conn.close()
        self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)

        if parsed.path == "/orders":
            try:
                data = json.loads(raw_body.decode("utf-8"))
                order_id = str(data["order_id"]).strip()
                customer = str(data.get("customer_name", "Khach hang")).strip()
                amount = int(data["amount"])
                currency = str(data.get("currency", "VND")).strip()
                if amount <= 0:
                    raise ValueError("Amount must be > 0")
            except Exception as e:
                self._send_json(400, {"error": f"Dữ liệu đơn hàng không hợp lệ: {e}"})
                return

            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO orders VALUES (?, ?, ?, ?, 'PENDING', ?)",
                    (order_id, customer, amount, currency, int(time.time())),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                self._send_json(409, {"error": "order_id đã tồn tại"})
                return
            conn.close()
            self._send_json(201, {"message": "Tạo đơn hàng thành công", "order_id": order_id})
            return

        if parsed.path == "/webhook/payment":
            received_sig = self.headers.get("X-Signature-HMAC-SHA256", "").strip()
            code, res = process_webhook_logic(raw_body, received_sig)
            self._send_json(code, res)
            return

        if parsed.path == "/simulate-gateway":
            req_data = json.loads(raw_body.decode("utf-8"))
            mode = req_data.get("mode", "valid")
            webhook_payload = {
                "tx_id": req_data["tx_id"],
                "order_id": req_data["order_id"],
                "amount": int(req_data["amount"]),
                "currency": req_data.get("currency", "VND"),
                "status": req_data.get("status", "SUCCESS"),
                "timestamp": int(time.time()),
            }
            wh_raw = json.dumps(webhook_payload).encode("utf-8")
            secret = b"wrong-secret-key" if mode == "fake_hmac" else WEBHOOK_SECRET
            sig = compute_hmac(wh_raw, secret)
            code, res = process_webhook_logic(wh_raw, sig)
            self._send_json(code, {
                "http_status": code,
                "hmac_signature_sent": sig,
                "webhook_payload": webhook_payload,
                "gshop_response": res,
            })
            return

        self._send_json(404, {"error": "Endpoint not found"})

    def log_message(self, format, *args):
        print(f"[G-SHOP] {self.address_string()} - {format % args}")


def run():
    init_db()
    server = ThreadingHTTPServer(("127.0.0.1", 8443), GShopHandler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=os.path.join(CERT_DIR, "server.crt"),
        keyfile=os.path.join(CERT_DIR, "server.key"),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print("G-Shop Web & HTTPS Demo đang chạy tại https://127.0.0.1:8443")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐã dừng server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
