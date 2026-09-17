import os
import json
import hashlib
import datetime as dt
import base64
import io
from functools import wraps
from urllib.parse import urlencode

import pandas as pd
import requests
import jwt
from flask import Flask, request, jsonify, render_template, redirect
from dotenv import load_dotenv

load_dotenv()

# =========================
# Config
# =========================
APP_DIR = os.path.dirname(__file__)
TOKENS_FILE = os.path.join(APP_DIR, "tokens.json")
LICENSE_FILE = os.path.join(APP_DIR, "licenses.json")

JWT_SECRET = os.getenv("JWT_SECRET", "dev_jwt_change_me")
SECRET_KEY = os.getenv("SECRET_KEY", "dev_change_me")

AO_IA_BULK_SAVE_PATH = os.getenv("AO_IA_BULK_SAVE_PATH", "/api/item-adjustment/bulk-save.do")

OAUTH_AUTHORIZE_URL = "https://account.accurate.id/oauth/authorize"
OAUTH_TOKEN_URL = "https://account.accurate.id/oauth/token"
ACCOUNT_DB_LIST_URL = "https://account.accurate.id/api/db-list.do"
ACCOUNT_OPEN_DB_URL = "https://account.accurate.id/api/open-db.do"

# Debug store
LAST_DEBUG = {
    "time": None,
    "form_sample": None,
    "url": None,
    "headers": None,
    "response_status": None,
    "response": None,
    "summary": None,
}

IA_TEMPLATE_COLUMNS = [
    "SEQ", "NUMBER", "TRANSDATE", "ADJUSTMENTACCOUNTNO", "DESCRIPTION", "BRANCHNAME",
    "ADJUSTMENTTYPE", "ITEMNO", "QUANTITY", "UNITCOST", "UNIT", "WAREHOUSE",
    "DETAILNAME", "DETAILNOTES", "DEPARTMENT", "PROJECT",
    "DATACLASSIFICATION1NAME", "DATACLASSIFICATION2NAME", "DATACLASSIFICATION3NAME",
    "DATACLASSIFICATION4NAME", "DATACLASSIFICATION5NAME", "DATACLASSIFICATION6NAME",
    "DATACLASSIFICATION7NAME", "DATACLASSIFICATION8NAME", "DATACLASSIFICATION9NAME",
    "DATACLASSIFICATION10NAME"
]

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# =========================
# Utils: token file
# =========================
def save_tokens(data: dict):
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_tokens():
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            txt = f.read().strip()
            if not txt:
                return {}
            return json.loads(txt)
    except Exception:
        return {}


# =========================
# Utils: license & auth
# =========================
def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_licenses():
    if not os.path.exists(LICENSE_FILE):
        return [
            {
                "email": "demo@aca-aol.id",
                "password_sha256": sha256("1234"),
                "active": True,
                "expires": None,
                "customer_name": "Demo User",
            }
        ]
    with open(LICENSE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def license_valid(email: str, password: str):
    licenses = load_licenses()
    email = (email or "").strip().lower()

    lic = next(
        (x for x in licenses if str(x.get("email", "")).strip().lower() == email),
        None
    )

    if not lic:
        return False, "Email tidak terdaftar", None

    if not lic.get("active"):
        return False, "Akun tidak aktif", None

    expires = lic.get("expires")
    if expires:
        try:
            exp_dt = dt.datetime.fromisoformat(expires + "T23:59:59")
            if dt.datetime.now() > exp_dt:
                return False, "Akun expired", None
        except Exception:
            return False, "Format expires di licenses.json salah", None

    if sha256(password) != lic.get("password_sha256"):
        return False, "Password salah", None

    return True, "OK", lic


def make_token(email: str) -> str:
    payload = {
        "email": email,
        "exp": dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"ok": False, "message": "Unauthorized"}), 401
        token = auth[7:]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except Exception:
            return jsonify({"ok": False, "message": "Invalid session"}), 401
        return fn(*args, **kwargs)

    return wrapper


# =========================
# OAuth helpers
# =========================
def refresh_access_token_if_needed():
    tokens = load_tokens()
    access_token = (tokens.get("access_token") or "").strip()
    refresh_token = (tokens.get("refresh_token") or "").strip()
    expires_at = (tokens.get("expires_at") or "").strip()

    if not access_token:
        return tokens

    if not expires_at:
        return tokens

    try:
        exp = dt.datetime.fromisoformat(expires_at)
        if dt.datetime.now() < exp - dt.timedelta(minutes=2):
            return tokens
    except Exception:
        return tokens

    if not refresh_token:
        return tokens

    client_id = (os.getenv("AO_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("AO_CLIENT_SECRET") or "").strip()
    if not client_id or not client_secret:
        return tokens

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {basic}"}
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}

    r = requests.post(OAUTH_TOKEN_URL, headers=headers, data=data, timeout=60)
    if not r.ok:
        return tokens

    j = r.json()
    expires_in = int(j.get("expires_in") or 3600)
    new_exp = dt.datetime.now() + dt.timedelta(seconds=expires_in)

    tokens.update(
        {
            "access_token": j.get("access_token"),
            "refresh_token": j.get("refresh_token") or refresh_token,
            "expires_at": new_exp.isoformat(),
            "updated_at": dt.datetime.now().isoformat(),
        }
    )
    save_tokens(tokens)
    return tokens


def accurate_post(path: str, data: dict):
    tokens = refresh_access_token_if_needed()
    access_token = (tokens.get("access_token") or "").strip()
    host = (tokens.get("host") or "").strip()
    x_session_id = (tokens.get("x_session_id") or "").strip()

    if not access_token or not host or not x_session_id:
        raise ValueError("OAuth belum lengkap. Connect + pilih DB dulu.")

    url = f"{host}/accurate{path}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Session-ID": x_session_id,
        "Accept": "application/json",
    }

    return requests.post(url, headers=headers, data=data, timeout=120)


# =========================
# Excel helpers
# =========================
def normalize_column_name(col):
    return str(col).strip().upper()


def parse_date_ddmmyyyy(val):
    if val is None:
        return None

    if isinstance(val, (dt.datetime, dt.date)):
        d = val.date() if isinstance(val, dt.datetime) else val
        return d.strftime("%d/%m/%Y")

    if isinstance(val, (int, float)) and str(val).strip() != "":
        try:
            base = dt.datetime(1899, 12, 30)
            d = base + dt.timedelta(days=float(val))
            return d.strftime("%d/%m/%Y")
        except Exception:
            pass

    s = str(val).strip()
    if not s:
        return None

    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y"):
        try:
            d = dt.datetime.strptime(s, fmt)
            return d.strftime("%d/%m/%Y")
        except Exception:
            continue

    try:
        d = pd.to_datetime(s, dayfirst=True, errors="raise")
        return d.strftime("%d/%m/%Y")
    except Exception:
        return None


def parse_bool(val):
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "y", "ya"):
        return True
    if s in ("false", "0", "no", "n", "tidak", ""):
        return False
    return None


def parse_money(val, default=None):
    if val is None:
        return default

    if isinstance(val, (int, float)) and not pd.isna(val):
        return float(val)

    s = str(val).strip()
    if s == "":
        return default

    try:
        return float(s.replace(",", ""))
    except Exception:
        return default


# =========================
# Inventory Adjustment Builder
# =========================
def build_inventory_adjustment_payload_from_df(df: pd.DataFrame):
    df = df.rename(columns=lambda c: normalize_column_name(c))
    df = df.fillna("")

    required_cols = ["NUMBER", "TRANSDATE", "ADJUSTMENTTYPE", "ITEMNO", "QUANTITY"]
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Kolom wajib tidak ada: {col}")

    valid_types = {"ADJUSTMENT_IN", "ADJUSTMENT_OUT", "ADJUSTMENT_STOCK"}
    normalized_rows = []

    for idx, row in df.iterrows():
        line_no = idx + 2
        number = str(row.get("NUMBER", "")).strip()
        if not number:
            raise ValueError(f"Row {line_no}: NUMBER kosong")

        trans_date = parse_date_ddmmyyyy(row.get("TRANSDATE"))
        if not trans_date:
            raise ValueError(f"Row {line_no}: TRANSDATE tidak valid")

        adjustment_type = str(row.get("ADJUSTMENTTYPE", "")).strip().upper()
        if adjustment_type not in valid_types:
            raise ValueError(
                f"Row {line_no}: ADJUSTMENTTYPE harus ADJUSTMENT_IN, ADJUSTMENT_OUT, atau ADJUSTMENT_STOCK"
            )

        item_no = str(row.get("ITEMNO", "")).strip()
        if not item_no:
            raise ValueError(f"Row {line_no}: ITEMNO kosong")

        quantity = parse_money(row.get("QUANTITY"))
        if quantity is None or quantity <= 0:
            raise ValueError(f"Row {line_no}: QUANTITY harus angka lebih besar dari 0")

        unit_cost = parse_money(row.get("UNITCOST"))
        if adjustment_type == "ADJUSTMENT_IN" and unit_cost is None:
            raise ValueError(f"Row {line_no}: UNITCOST wajib untuk ADJUSTMENT_IN")
        if unit_cost is not None and unit_cost < 0:
            raise ValueError(f"Row {line_no}: UNITCOST tidak boleh negatif")

        normalized_rows.append({
            **row.to_dict(),
            "NUMBER": number,
            "TRANSDATE": trans_date,
            "ADJUSTMENTTYPE": adjustment_type,
            "ITEMNO": item_no,
            "QUANTITY": quantity,
            "UNITCOST": unit_cost,
            "_ROW": line_no,
        })

    grouped = {}
    for r in normalized_rows:
        grouped.setdefault(r["NUMBER"], []).append(r)

    data = []
    for number, rows in grouped.items():
        def seq_key(x):
            raw = str(x.get("SEQ", "")).strip()
            try:
                return int(float(raw))
            except Exception:
                return 999999

        rows = sorted(rows, key=seq_key)
        head = rows[0]

        # Header values must be consistent for all lines under the same NUMBER.
        header_cols = ["TRANSDATE", "ADJUSTMENTACCOUNTNO", "DESCRIPTION", "BRANCHNAME"]
        for col in header_cols:
            first = str(head.get(col, "")).strip()
            for r in rows[1:]:
                current = str(r.get(col, "")).strip()
                if current != first:
                    raise ValueError(
                        f"NUMBER {number}: nilai {col} tidak konsisten (cek row {r.get('_ROW')})"
                    )

        tx = {
            "number": number,
            "transDate": head["TRANSDATE"],
            "detailItem": [],
        }

        adjustment_account = str(head.get("ADJUSTMENTACCOUNTNO", "")).strip()
        if adjustment_account:
            tx["adjustmentAccountNo"] = adjustment_account

        description = str(head.get("DESCRIPTION", "")).strip()
        if description:
            tx["description"] = description

        branch_name = str(head.get("BRANCHNAME", "")).strip()
        if branch_name:
            tx["branchName"] = branch_name

        for r in rows:
            item = {
                "itemAdjustmentType": r["ADJUSTMENTTYPE"],
                "itemNo": r["ITEMNO"],
                "quantity": r["QUANTITY"],
            }

            if r.get("UNITCOST") is not None:
                item["unitCost"] = r["UNITCOST"]

            detail_map = {
                "UNIT": "itemUnitName",
                "WAREHOUSE": "warehouseName",
                "DETAILNAME": "detailName",
                "DETAILNOTES": "detailNotes",
                "DEPARTMENT": "departmentName",
                "PROJECT": "projectNo",
            }
            for src, dst in detail_map.items():
                val = str(r.get(src, "")).strip()
                if val:
                    item[dst] = val

            for i in range(1, 11):
                src = f"DATACLASSIFICATION{i}NAME"
                val = str(r.get(src, "")).strip()
                if val:
                    item[f"dataClassification{i}Name"] = val

            tx["detailItem"].append(item)

        data.append(tx)

    return {"data": data}


def inventory_adjustment_bulk_form_params(transactions: list[dict]) -> dict:
    out = {}
    for tx_i, tx in enumerate(transactions):
        for k, v in tx.items():
            if k == "detailItem" or v in (None, ""):
                continue
            out[f"data[{tx_i}].{k}"] = v

        for item_i, item in enumerate(tx.get("detailItem", [])):
            for k, v in item.items():
                if v in (None, ""):
                    continue
                out[f"data[{tx_i}].detailItem[{item_i}].{k}"] = v

    return {k: str(v) for k, v in out.items()}


def extract_accurate_errors(resp_json):
    if not isinstance(resp_json, dict):
        return ["Response Accurate tidak dikenali."]
    if isinstance(resp_json.get("d"), list):
        return [str(x) for x in resp_json.get("d", [])]
    if resp_json.get("d"):
        return [str(resp_json.get("d"))]
    if resp_json.get("message"):
        return [str(resp_json.get("message"))]
    if resp_json.get("error"):
        return [str(resp_json.get("error"))]
    return ["Transaksi ditolak Accurate."]


# =========================
# Routes: UI
# =========================
@app.get("/")
def home():
    return render_template("index.html")


# =========================
# Routes: login/license
# =========================
@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return jsonify({"ok": False, "message": "Email & password wajib"}), 400

    ok, msg, lic = license_valid(email, password)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 401

    token = make_token(email)

    return jsonify({
        "ok": True,
        "token": token,
        "customer_name": lic.get("customer_name"),
        "email": email
    })


# =========================
# Routes: status
# =========================
@app.get("/api/ao-status")
def api_ao_status():
    tokens = load_tokens()
    return jsonify(
        {
            "ok": True,
            "has_token": bool((tokens.get("access_token") or "").strip()),
            "has_session": bool((tokens.get("host") or "").strip()) and bool((tokens.get("x_session_id") or "").strip()),
            "db_id": tokens.get("db_id"),
            "db_alias": tokens.get("db_alias"),
        }
    )


@app.get("/api/debug-last")
def api_debug_last():
    return jsonify({"ok": True, **LAST_DEBUG})


@app.post("/api/ao-logout")
def api_ao_logout():
    if os.path.exists(TOKENS_FILE):
        os.remove(TOKENS_FILE)
    return jsonify({"ok": True})


# =========================
# Routes: build payload Inventory Adjustment
# =========================
@app.post("/api/build-inventory-adjustment")
@require_auth
def api_build_inventory_adjustment():
    if "file" not in request.files:
        return jsonify({"ok": False, "message": "File tidak ditemukan"}), 400

    f = request.files["file"]
    if not f.filename.lower().endswith((".xlsx", ".xls")):
        return jsonify({"ok": False, "message": "File harus Excel (.xlsx/.xls)"}), 400

    try:
        df = pd.read_excel(f)
        built = build_inventory_adjustment_payload_from_df(df)
        tx_count = len(built.get("data", []))
        line_count = sum(len(x.get("detailItem", [])) for x in built.get("data", []))
        return jsonify({
            "ok": True,
            "payload": built,
            "summary": {"transactions": tx_count, "lines": line_count}
        })
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 400


# =========================
# Routes: bulk import Inventory Adjustment
# =========================
@app.post("/api/import-inventory-adjustment")
@require_auth
def api_import_inventory_adjustment():
    body = request.get_json(silent=True) or {}
    payload = body.get("payload")
    transactions = (payload or {}).get("data") or []
    if not transactions:
        return jsonify({"ok": False, "message": "payload kosong"}), 400

    tokens = refresh_access_token_if_needed()
    access_token = (tokens.get("access_token") or "").strip()
    host = (tokens.get("host") or "").strip()
    x_session = (tokens.get("x_session_id") or "").strip()
    if not access_token or not host or not x_session:
        return jsonify({"ok": False, "message": "OAuth belum lengkap. Connect + pilih DB dulu."}), 400

    url = f"{host}/accurate{AO_IA_BULK_SAVE_PATH}"
    results = []
    success_count = 0
    failed_count = 0
    batch_size = 100

    try:
        for batch_start in range(0, len(transactions), batch_size):
            batch = transactions[batch_start:batch_start + batch_size]
            form_params = inventory_adjustment_bulk_form_params(batch)
            r = accurate_post(AO_IA_BULK_SAVE_PATH, data=form_params)
            try:
                resp_json = r.json()
            except Exception:
                resp_json = {"raw": r.text}

            batch_ok = bool(r.ok and isinstance(resp_json, dict) and resp_json.get("s") is True)
            errors = [] if batch_ok else extract_accurate_errors(resp_json)

            for offset, tx in enumerate(batch):
                idx = batch_start + offset + 1
                tx_ok = batch_ok
                if tx_ok:
                    success_count += 1
                else:
                    failed_count += 1
                results.append({
                    "index": idx,
                    "number": str(tx.get("number") or f"TX-{idx}"),
                    "transDate": str(tx.get("transDate") or "-"),
                    "ok": tx_ok,
                    "errors": errors,
                    "raw_response": resp_json if not tx_ok else None,
                })

            if batch_start == 0:
                LAST_DEBUG["form_sample"] = dict(list(form_params.items())[:120])

        summary = {"total": len(results), "success": success_count, "failed": failed_count}
        LAST_DEBUG["time"] = dt.datetime.now().isoformat()
        LAST_DEBUG["url"] = url
        LAST_DEBUG["headers"] = {"Authorization": "Bearer ***", "X-Session-ID": x_session}
        LAST_DEBUG["response_status"] = 200 if failed_count == 0 else 400
        LAST_DEBUG["response"] = results
        LAST_DEBUG["summary"] = summary

        status = 200 if failed_count == 0 else 400
        return jsonify({
            "ok": failed_count == 0,
            "message": "Import berhasil" if failed_count == 0 else "Import selesai dengan catatan",
            "summary": summary,
            "results": results,
        }), status
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500


# =========================
# Routes: OAuth
# =========================
@app.get("/oauth/start")
def oauth_start():
    client_id = (os.getenv("AO_CLIENT_ID") or "").strip()
    redirect_uri = (os.getenv("AO_REDIRECT_URI") or "").strip()
    scope = (os.getenv("AO_SCOPE") or "").strip()

    if not client_id or not redirect_uri or not scope:
        return (
            jsonify(
                {
                    "ok": False,
                    "message": "OAuth env belum lengkap. Isi AO_CLIENT_ID, AO_REDIRECT_URI, AO_SCOPE di .env",
                }
            ),
            500,
        )

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    url = OAUTH_AUTHORIZE_URL + "?" + urlencode(params)
    return redirect(url, code=302)


@app.get("/oauth/callback")
def oauth_callback():
    code = (request.args.get("code") or "").strip()
    if not code:
        return "Tidak ada parameter code. OAuth ditolak / gagal.", 400

    client_id = (os.getenv("AO_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("AO_CLIENT_SECRET") or "").strip()
    redirect_uri = (os.getenv("AO_REDIRECT_URI") or "").strip()
    if not client_id or not client_secret or not redirect_uri:
        return "OAuth env belum lengkap. Isi AO_CLIENT_ID/AO_CLIENT_SECRET/AO_REDIRECT_URI di .env", 500

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {basic}"}
    data = {"code": code, "grant_type": "authorization_code", "redirect_uri": redirect_uri}

    r = requests.post(OAUTH_TOKEN_URL, headers=headers, data=data, timeout=60)
    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text}

    if not r.ok:
        return jsonify({"ok": False, "message": "Gagal tukar code ke token", "response": j}), r.status_code

    expires_in = int(j.get("expires_in") or 3600)
    exp = dt.datetime.now() + dt.timedelta(seconds=expires_in)

    tokens = load_tokens()
    tokens.update(
        {
            "access_token": j.get("access_token"),
            "refresh_token": j.get("refresh_token"),
            "scope": j.get("scope"),
            "token_type": j.get("token_type"),
            "expires_at": exp.isoformat(),
            "updated_at": dt.datetime.now().isoformat(),
        }
    )
    save_tokens(tokens)

    return """
    <script>
      window.location.href = "/";
    </script>
    """


# =========================
# Routes: db list & open db
# =========================
@app.get("/api/db-list")
def api_db_list():
    tokens = refresh_access_token_if_needed()
    access_token = (tokens.get("access_token") or "").strip()
    if not access_token:
        return jsonify({"ok": False, "message": "Belum connect OAuth. Klik Connect Accurate dulu."}), 401

    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(ACCOUNT_DB_LIST_URL, headers=headers, timeout=60)

    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text}

    if not r.ok:
        return jsonify({"ok": False, "message": "db-list gagal", "status": r.status_code, "response": j}), r.status_code

    return jsonify({"ok": True, "response": j})


@app.post("/api/open-db")
def api_open_db():
    body = request.get_json(silent=True) or {}
    db_id = str(body.get("id") or "").strip()
    db_alias = str(body.get("alias") or "").strip()

    tokens = refresh_access_token_if_needed()
    access_token = (tokens.get("access_token") or "").strip()
    if not access_token:
        return jsonify({"ok": False, "message": "Belum connect OAuth."}), 401
    if not db_id:
        return jsonify({"ok": False, "message": "db id kosong."}), 400

    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(ACCOUNT_OPEN_DB_URL, headers=headers, params={"id": db_id}, timeout=60)

    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text}

    if not r.ok:
        return jsonify({"ok": False, "message": "open-db gagal", "status": r.status_code, "response": j}), r.status_code

    tokens.update(
        {
            "db_id": db_id,
            "db_alias": db_alias or tokens.get("db_alias"),
            "host": j.get("host"),
            "x_session_id": j.get("session"),
            "updated_at": dt.datetime.now().isoformat(),
        }
    )
    save_tokens(tokens)

    return jsonify({"ok": True, "response": j})


# =========================
# Template download (Excel)
# =========================
@app.get("/api/template")
def api_template():
    sample_rows = [
        {
            "SEQ": 1, "NUMBER": "IA-17092026-001", "TRANSDATE": "17/09/2026",
            "ADJUSTMENTACCOUNTNO": "", "DESCRIPTION": "Stock opname", "BRANCHNAME": "",
            "ADJUSTMENTTYPE": "ADJUSTMENT_IN", "ITEMNO": "ITEM-001", "QUANTITY": 10,
            "UNITCOST": 25000, "UNIT": "PCS", "WAREHOUSE": "Gudang Utama",
            "DETAILNAME": "", "DETAILNOTES": "Selisih stock opname", "DEPARTMENT": "", "PROJECT": "",
        },
        {
            "SEQ": 2, "NUMBER": "IA-17092026-001", "TRANSDATE": "17/09/2026",
            "ADJUSTMENTACCOUNTNO": "", "DESCRIPTION": "Stock opname", "BRANCHNAME": "",
            "ADJUSTMENTTYPE": "ADJUSTMENT_OUT", "ITEMNO": "ITEM-002", "QUANTITY": 3,
            "UNITCOST": "", "UNIT": "PCS", "WAREHOUSE": "Gudang Utama",
            "DETAILNAME": "", "DETAILNOTES": "Barang rusak", "DEPARTMENT": "", "PROJECT": "",
        },
    ]
    rows = []
    for sample in sample_rows:
        rows.append({col: sample.get(col, "") for col in IA_TEMPLATE_COLUMNS})

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        pd.DataFrame(rows, columns=IA_TEMPLATE_COLUMNS).to_excel(writer, index=False, sheet_name="Inventory Adjustment")
        ws = writer.book["Inventory Adjustment"]
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for cell in ws[1]:
            cell.font = cell.font.copy(bold=True, color="FFFFFF")
            cell.fill = __import__("openpyxl").styles.PatternFill("solid", fgColor="1F4E78")
        widths = {
            "A": 8, "B": 22, "C": 14, "D": 22, "E": 24, "F": 18, "G": 22, "H": 18,
            "I": 12, "J": 14, "K": 12, "L": 20, "M": 24, "N": 28, "O": 18, "P": 18,
        }
        for col, width in widths.items():
            ws.column_dimensions[col].width = width
        for col_idx in range(17, len(IA_TEMPLATE_COLUMNS) + 1):
            ws.column_dimensions[__import__("openpyxl").utils.get_column_letter(col_idx)].width = 24

    output.seek(0)
    return app.response_class(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=template-inventory-adjustment.xlsx"},
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "3000"))
    app.run(host="0.0.0.0", port=port, debug=False)