"""Black-box attack client for GASC-Governor-Gateway.

Only knowledge used: the brief, the two JSON schemas, and the ES256 signing key
we were handed as the disposable-instance operator. No source was read.
"""
import json, uuid, hashlib, datetime, sys
import urllib.request, urllib.error
import jwt  # PyJWT
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

BASE = "http://127.0.0.1:8000"
PRIV = open("/tmp/gasc-governor-jwt-private.pem").read()

def now(offset_s=0):
    t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset_s)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def sha256hex(b):
    if isinstance(b, str): b = b.encode()
    return hashlib.sha256(b).hexdigest()

def mint_jwt(claims, alg="ES256", key=None, headers=None):
    key = key if key is not None else PRIV
    return jwt.encode(claims, key, algorithm=alg, headers=headers or {})

# ---- agent NHI ECDSA-P256 signing key (for agent_signature) ----
_agent_key = ec.generate_private_key(ec.SECP256R1())
def agent_pub_pem():
    return _agent_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def agent_sign(data_bytes):
    der = _agent_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
    # also provide raw r||s form
    r, s = asym_utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return der.hex(), raw.hex()

def req(method, path, body=None, token=None, raw_headers=None, expect_json=True, timeout=15):
    url = BASE + path
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if raw_headers:
        headers.update(raw_headers)
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            code = resp.getcode()
            raw = resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        code = e.code
        raw = e.read().decode(errors="replace")
    except Exception as e:
        return {"status": None, "error": repr(e)}
    out = {"status": code, "body": raw}
    if expect_json:
        try: out["json"] = json.loads(raw)
        except Exception: pass
    return out

def pp(label, res):
    b = res.get("body", res.get("error", ""))
    if len(b) > 1200: b = b[:1200] + "...<truncated>"
    print(f"### {label}\n  status={res.get('status')}\n  {b}\n")

if __name__ == "__main__":
    # smoke
    for p in ["/readyz", "/livez", "/ready"]:
        pp(p, req("GET", p))
