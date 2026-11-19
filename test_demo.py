import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.request

BASE_URL = "https://127.0.0.1:8443"
WEBHOOK_SECRET = b"gshop-payment-gateway-hmac-secret-key"
CA_PATH = "/root/gshop-demo/certs/rootCA.crt"

ssl_ctx = ssl.create_default_context(cafile=CA_PATH)


def sign_hmac(raw_bytes: bytes, secret: bytes = WEBHOOK_SECRET) -> str:
    return hmac.new(secret, raw_bytes, hashlib.sha256).hexdigest()


def post_webhook(payload: dict, secret: bytes = WEBHOOK_SECRET):
    raw = json.dumps(payload).encode("utf-8")
    sig = sign_hmac(raw, secret)
    req = urllib.request.Request(
        f"{BASE_URL}/webhook/payment",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Signature-HMAC-SHA256": sig,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ssl_ctx) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def get_json(path: str):
    with urllib.request.urlopen(f"{BASE_URL}{path}", context=ssl_ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


if __name__ == "__main__":
    now = int(time.time())

    print("1. [Hợp lệ] Thanh toán đơn ORD-1001 (2.500.000 VND) có chữ ký HMAC đúng:")
    valid_tx = {
        "tx_id": f"TX-{now}-01",
        "order_id": "ORD-1001",
        "amount": 2500000,
        "currency": "VND",
        "status": "SUCCESS",
        "timestamp": now,
    }
    print("  ->", post_webhook(valid_tx))

    print("\n2. [Chống Replay / Trùng lặp] Gửi lại đúng giao dịch TX trên lần nữa:")
    print("  ->", post_webhook(valid_tx))

    print("\n3. [Chống giả mạo] Gửi webhook với sai secret key:")
    fake_tx = {
        "tx_id": f"TX-{now}-02",
        "order_id": "ORD-1002",
        "amount": 1200000,
        "currency": "VND",
        "status": "SUCCESS",
        "timestamp": now,
    }
    print("  ->", post_webhook(fake_tx, secret=b"wrong-attacker-key"))

    print("\n4. [Chống sửa số tiền] Ký HMAC hợp lệ nhưng amount = 1000 (đơn thật là 1.200.000):")
    tampered_amount_tx = {
        "tx_id": f"TX-{now}-03",
        "order_id": "ORD-1002",
        "amount": 1000,
        "currency": "VND",
        "status": "SUCCESS",
        "timestamp": now,
    }
    print("  ->", post_webhook(tampered_amount_tx))

    print("\n5. Trạng thái đơn hàng hiện tại:")
    print(json.dumps(get_json("/orders"), indent=2, ensure_ascii=False))

    print("\n6. Dữ liệu giao dịch đã mã hóa AES-256-GCM trong SQLite:")
    print(json.dumps(get_json("/transactions"), indent=2, ensure_ascii=False))
