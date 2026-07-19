#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — Panel webowy IoT (Flask + RBAC + ciemny motyw GitHub-dark)
Praca magisterska: Bezpieczenstwo IoT — porownanie algorytmow szyfrowania
"""
import io
import csv
import pytz
from datetime import datetime
from functools import wraps

import paho.mqtt.publish as mqtt_publish
from flask import (Flask, render_template_string, request, session,
                   redirect, url_for, make_response, flash)
from influxdb_client import InfluxDBClient

# ═══════════════════════════════════════════════════════════════════════════════
# KONFIGURACJA
# ═══════════════════════════════════════════════════════════════════════════════
INFLUX_TOKEN  = "TWOJ_INFLUXDB_TOKEN"   # <-- token z InfluxDB UI: Data → API Tokens
INFLUX_ORG    = "MojaMagisterka"
INFLUX_BUCKET = "dane_esp"
INFLUX_URL    = "http://localhost:8086"
MQTT_BROKER   = "127.0.0.1"

TOPIK_SET_SECURITY = "/plytka_antywlamaniowa/set_algorytm"
TOPIK_SET_ENV      = "/plytka_srodowiskoa/set_algorytm"   # literowka celowa

STREFA_CZASOWA = pytz.timezone("Europe/Warsaw")

NAZWY_ALGORYTMOW = {
    "0": "0 — Czysty tekst",
    "1": "1 — Base64",
    "2": "2 — Cezar-3",
    "3": "3 — XOR-1234",
    "4": "4 — Vigenere-TAJNE",
    "5": "5 — RC4",
    "6": "6 — AES-128-ECB",
    "7": "7 — AES-128-CBC",
    "8": "8 — AES-128-GCM",
}

# ═══════════════════════════════════════════════════════════════════════════════
# FLASK + INFLUXDB
# ═══════════════════════════════════════════════════════════════════════════════
aplikacja = Flask(__name__)
aplikacja.secret_key = "ZMIEN_NA_LOSOWY_CIAG_ZNAKOW"   # <-- wygeneruj: python3 -c "import secrets; print(secrets.token_hex(32))"

_klient_influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
_api_zapytan   = _klient_influx.query_api()


# ═══════════════════════════════════════════════════════════════════════════════
# RBAC — dekoratory dostepu
# ═══════════════════════════════════════════════════════════════════════════════
def wymaga_logowania(f):
    @wraps(f)
    def _w(*a, **kw):
        if not session.get("zalogowany"):
            return redirect(url_for("logowanie"))
        return f(*a, **kw)
    return _w


def wymaga_admina(f):
    @wraps(f)
    def _w(*a, **kw):
        if not session.get("zalogowany"):
            return redirect(url_for("logowanie"))
        if session.get("rola") != "admin":
            return ("<h1 style='font-family:monospace;color:#da3633;"
                    "text-align:center;margin-top:15%'>403 — Brak uprawnien</h1>", 403)
        return f(*a, **kw)
    return _w


# ═══════════════════════════════════════════════════════════════════════════════
# INFLUXDB — funkcje pomocnicze
# ═══════════════════════════════════════════════════════════════════════════════
def _flux(zapytanie: str) -> list:
    """Wykonuje zapytanie Flux, zwraca liste slownikow values."""
    try:
        tabele  = _api_zapytan.query(zapytanie, org=INFLUX_ORG)
        rekordy = []
        for tabela in tabele:
            for rekord in tabela.records:
                rekordy.append(rekord.values)
        return rekordy
    except Exception as ex:
        print(f"[InfluxDB] Blad zapytania: {ex}")
        return []


def _czas_str(v) -> str:
    """Konwertuje timestamp InfluxDB do lokalnego stringa."""
    if v is None:
        return "?"
    try:
        return v.astimezone(STREFA_CZASOWA).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(v)


def _f(r: dict, k: str, d=0.0) -> float:
    try:   return float(r.get(k, d))
    except (TypeError, ValueError): return d


def _i(r: dict, k: str, d=0) -> int:
    try:   return int(float(r.get(k, d)))
    except (TypeError, ValueError): return d


def _s(r: dict, k: str, d="—") -> str:
    v = r.get(k)
    return str(v) if v is not None else d


def pobierz_ostatni(urzadzenie: str) -> dict:
    """Pobiera ostatni rekord pomiarowy (nie heartbeat) danego urzadzenia."""
    q = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "pomiary")
  |> filter(fn: (r) => r.urzadzenie == "{urzadzenie}")
  |> filter(fn: (r) => r._field != "heartbeat")
  |> pivot(rowKey: ["_time", "urzadzenie"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"], desc: true)
  |> limit(n: 1)
'''
    rekordy = _flux(q)
    return rekordy[0] if rekordy else {}


def sprawdz_online(urzadzenie: str) -> bool:
    """True jesli heartbeat urzadzenia byl w ostatnich 20 sekundach."""
    q = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -20s)
  |> filter(fn: (r) => r._measurement == "pomiary"
                    and r.urzadzenie == "{urzadzenie}"
                    and r._field == "heartbeat")
  |> count()
'''
    for r in _flux(q):
        try:
            if int(r.get("_value", 0)) > 0:
                return True
        except (TypeError, ValueError):
            pass
    return False


def pobierz_historie(start: str, stop: str = "now()", limit: int = 200) -> list:
    """Pobiera posortowane rekordy z obu urzadzen za podany zakres czasu."""
    q = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: {start}, stop: {stop})
  |> filter(fn: (r) => r._measurement == "pomiary")
  |> filter(fn: (r) => r._field != "heartbeat")
  |> pivot(rowKey: ["_time", "urzadzenie"], columnKey: ["_field"], valueColumn: "_value")
'''
    # Sortowanie i limit robimy w Pythonie, bo pivot() grupuje wyniki wg
    # urzadzenia — sort()/limit() we Fluxie dzialalyby osobno w kazdej grupie
    # (dawaloby to blok "security" nastepnie blok "environment" zamiast
    # jednego ciagu posortowanego po czasie).
    rekordy = _flux(q)
    rekordy.sort(key=lambda r: r.get("_time"), reverse=True)
    return [_przetworz_rekord(r) for r in rekordy[:limit]]


def pobierz_raw_enc(limit: int = 100) -> list:
    """Pobiera zaszyfrowane payloady z ostatniej godziny (widok uzytkownika)."""
    q = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "pomiary" and r._field == "raw_enc")
  |> sort(columns: ["_time"], desc: true)
  |> limit(n: {limit})
'''
    wyniki = []
    for r in _flux(q):
        wyniki.append({
            "czas":       _czas_str(r.get("_time")),
            "urzadzenie": _s(r, "urzadzenie"),
            "raw_enc":    str(r.get("_value", "")),
        })
    return wyniki


def _przetworz_rekord(r: dict) -> dict:
    """Konwertuje surowy rekord InfluxDB na slownik przyjazny szablonowi."""
    return {
        "czas":        _czas_str(r.get("_time")),
        "urzadzenie":  _s(r, "urzadzenie"),
        "status":      _s(r, "status"),
        "pir":         _i(r, "pir"),
        "drzwi":       _i(r, "drzwi"),
        "acc_x":       _f(r, "acc_x"),
        "acc_y":       _f(r, "acc_y"),
        "acc_z":       _f(r, "acc_z"),
        "temperatura": _f(r, "temperatura"),
        "wilgotnosc":  _f(r, "wilgotnosc"),
        "cisnienie":   _f(r, "cisnienie"),
        "gazy":        _f(r, "gazy"),
        "swiatlo":     _f(r, "swiatlo"),
        "dzwiek":      _i(r, "dzwiek"),
        "raw_enc":     _s(r, "raw_enc"),
        "uzyty_szyfr": _s(r, "uzyty_szyfr"),
        "data_hash":   _s(r, "data_hash"),
        "tx_hash":     _s(r, "tx_hash"),
    }


def _dt_local_do_rfc3339(dt_str: str) -> str:
    """Konwertuje datetime-local HTML (np. '2024-01-15T10:30') do RFC3339 UTC."""
    dt    = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M")
    dt_lc = STREFA_CZASOWA.localize(dt)
    dt_ut = dt_lc.astimezone(pytz.utc)
    return dt_ut.strftime("%Y-%m-%dT%H:%M:%SZ")


# ═══════════════════════════════════════════════════════════════════════════════
# CSS — wspolny ciemny motyw (GitHub dark, wbudowany w kazdy szablon)
# ═══════════════════════════════════════════════════════════════════════════════
_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#0d1117;
  color:#c9d1d9;min-height:100vh}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}

/* NAGLOWEK */
.hdr{background:#010409;border-bottom:1px solid #30363d;padding:12px 24px;
  display:flex;justify-content:space-between;align-items:center}
.hdr-logo{font-size:1.05rem;font-weight:700;color:#58a6ff;letter-spacing:.5px}
.hdr-right{display:flex;align-items:center;gap:10px}

/* ODZNAKI ONLINE/OFFLINE */
.badge{display:inline-block;padding:4px 12px;border-radius:12px;
  font-size:.78rem;font-weight:700}
.badge-on{background:#238636;color:#fff}
.badge-off{background:#21262d;color:#6e7681;border:1px solid #30363d}

/* ODLICZANIE */
.countdown{color:#6e7681;font-size:.8rem}

/* CONTENT */
.content{padding:20px 24px;max-width:1440px;margin:0 auto}

/* FLASH */
.flash{padding:10px 16px;border-radius:6px;margin-bottom:16px;font-size:.9rem}
.flash-ok{background:#1a4731;border:1px solid #238636;color:#3fb950}
.flash-err{background:#3d1a1a;border:1px solid #da3633;color:#f85149}

/* KARTY */
.cards-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px}
.card-title{font-size:.78rem;font-weight:700;text-transform:uppercase;
  letter-spacing:1px;color:#8b949e;margin-bottom:14px;
  border-bottom:1px solid #21262d;padding-bottom:8px}
.field-row{display:flex;justify-content:space-between;align-items:center;
  padding:5px 0;border-bottom:1px solid #161b22}
.field-label{color:#8b949e;font-size:.875rem}
.field-val{font-weight:500;font-size:.9rem}

/* STATUSY ALARM */
.s-alarm{color:#da3633;font-weight:800;animation:pls 1s ease-in-out infinite}
.s-czuwa{color:#3fb950;font-weight:700}
.s-off{color:#6e7681;font-weight:700}
@keyframes pls{0%,100%{opacity:1}50%{opacity:.45}}

/* MONO/KRYPTO */
.mono{font-family:'SFMono-Regular',Consolas,monospace;color:#b392f0;font-size:.82rem;
  background:#0d1117;padding:2px 6px;border-radius:4px;word-break:break-all}

/* PANEL ALGORYTMU */
.algo-panel{background:#161b22;border:1px solid #30363d;border-radius:8px;
  padding:16px 20px;margin-bottom:20px;display:flex;flex-wrap:wrap;
  align-items:center;gap:14px}
.algo-label{color:#58a6ff;font-weight:600;font-size:.9rem;white-space:nowrap}
select{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;
  border-radius:6px;padding:7px 12px;font-size:.875rem;cursor:pointer}
select:focus{outline:none;border-color:#58a6ff}

/* PRZYCISKI */
.btn{padding:7px 18px;border-radius:6px;border:none;font-size:.875rem;
  font-weight:600;cursor:pointer;transition:opacity .18s,transform .1s;
  white-space:nowrap}
.btn:hover{opacity:.82;transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn-green{background:#238636;color:#fff}
.btn-blue{background:#1f6feb;color:#fff}
.btn-gray{background:#21262d;color:#c9d1d9;border:1px solid #30363d}
.btn-red{background:#da3633;color:#fff}

/* TABELA */
.tbl-wrap{background:#161b22;border:1px solid #30363d;border-radius:8px;
  overflow:hidden;margin-bottom:20px}
.tbl-head{padding:14px 20px;display:flex;justify-content:space-between;
  align-items:center;border-bottom:1px solid #30363d}
.tbl-head-title{color:#c9d1d9;font-weight:600;font-size:.95rem}
table{width:100%;border-collapse:collapse;font-size:.82rem}
thead th{background:#21262d;color:#8b949e;padding:9px 12px;text-align:left;
  font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
  border-bottom:1px solid #30363d}
tbody tr:nth-child(even){background:#161b22}
tbody tr:nth-child(odd){background:#0d1117}
tbody tr:hover{background:#1c2128}
tbody td{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:middle}
.tr-alarm td:first-child{border-left:3px solid #da3633}
.tr-norm td:first-child{border-left:3px solid #3fb950}
.tr-env td:first-child{border-left:3px solid #388bfd}

/* HISTORIA */
.filter-bar{background:#161b22;border:1px solid #30363d;border-radius:8px;
  padding:16px 20px;margin-bottom:20px;display:flex;flex-wrap:wrap;
  align-items:center;gap:12px}
input[type=datetime-local]{background:#0d1117;color:#c9d1d9;
  border:1px solid #30363d;border-radius:6px;padding:7px 10px;font-size:.875rem}
input[type=datetime-local]:focus{outline:none;border-color:#58a6ff}

/* WIDOK UZYTKOWNIKA — raw payloady */
.raw-list{display:flex;flex-direction:column;gap:10px}
.raw-item{background:#161b22;border:1px solid #30363d;border-radius:8px;
  padding:14px 18px}
.raw-meta{font-size:.78rem;color:#6e7681;margin-bottom:6px;display:flex;gap:12px}
.raw-meta .dev-s{color:#f0883e;font-weight:700}
.raw-meta .dev-e{color:#388bfd;font-weight:700}
.raw-payload{font-family:'SFMono-Regular',Consolas,monospace;font-size:.8rem;
  color:#b392f0;word-break:break-all;line-height:1.5}

/* LOGIN */
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-card{background:#161b22;border:1px solid #30363d;border-radius:12px;
  padding:40px;width:360px;box-shadow:0 8px 32px rgba(0,0,0,.5)}
.login-logo{text-align:center;margin-bottom:28px}
.login-title{font-size:1.3rem;font-weight:700;color:#58a6ff}
.login-sub{font-size:.78rem;color:#6e7681;margin-top:4px}
.form-grp{margin-bottom:14px}
.form-grp label{display:block;font-size:.83rem;color:#8b949e;margin-bottom:5px}
.form-grp input{width:100%;padding:10px 14px;background:#0d1117;
  border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:.95rem;
  transition:border-color .2s}
.form-grp input:focus{outline:none;border-color:#58a6ff}
.btn-login{width:100%;padding:11px;background:#238636;color:#fff;border:none;
  border-radius:6px;font-size:1rem;font-weight:700;cursor:pointer;margin-top:6px;
  transition:background .2s}
.btn-login:hover{background:#2ea043}
.login-err{background:#3d1a1a;border:1px solid #da3633;color:#f85149;
  padding:9px 13px;border-radius:6px;margin-bottom:14px;font-size:.88rem}
.roles-hint{margin-top:18px;padding:12px;background:#21262d;border-radius:6px;
  font-size:.78rem;color:#6e7681;line-height:1.7}
.roles-hint b{color:#8b949e}
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SZABLON — STRONA LOGOWANIA
# ═══════════════════════════════════════════════════════════════════════════════
HTML_LOGIN = """<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>Logowanie — Panel Bezpieczenstwa IoT</title>
<style>{{ css }}</style>
</head>
<body>
<div class="login-wrap">
  <div class="login-card">
    <div class="login-logo">
      <div class="login-title">System bezpieczenstwa IoT</div>
      <div class="login-sub">Praca magisterska — Bezpieczenstwo IoT</div>
    </div>
    {% if blad %}
    <div class="login-err">{{ blad }}</div>
    {% endif %}
    <form method="POST" action="/login">
      <div class="form-grp">
        <label>Uzytkownik</label>
        <input type="text" name="login" placeholder="admin" required autofocus>
      </div>
      <div class="form-grp">
        <label>Haslo</label>
        <input type="password" name="haslo" placeholder="••••••" required>
      </div>
      <button type="submit" class="btn-login">Zaloguj sie</button>
    </form>
    <div class="roles-hint">
      <b>admin</b> / admin &nbsp;→&nbsp; pelny dostep + zmiana algorytmu<br>
      <b>user</b> / user &nbsp;&nbsp;&nbsp;&nbsp;→&nbsp; tylko zaszyfrowane payloady
    </div>
  </div>
</div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# SZABLON — DASHBOARD ADMINA
# ═══════════════════════════════════════════════════════════════════════════════
HTML_ADMIN = """<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<title>Panel IoT — Admin</title>
<style>{{ css }}</style>
</head>
<body>

<!-- NAGLOWEK -->
<div class="hdr">
  <div class="hdr-logo">System bezpieczenstwa IoT &nbsp;<span style="color:#6e7681;font-weight:400;font-size:.85rem">/ admin</span></div>
  <div class="hdr-right">
    <span class="badge {{ 'badge-on' if sec_online else 'badge-off' }}">
      {{ 'ONLINE' if sec_online else 'OFFLINE' }} &nbsp;Alarm
    </span>
    <span class="badge {{ 'badge-on' if env_online else 'badge-off' }}">
      {{ 'ONLINE' if env_online else 'OFFLINE' }} &nbsp;Srodowisko
    </span>
    <span class="countdown">odswiezenie za <span id="licz">5</span>s</span>
    <a href="/historia" class="btn btn-gray" style="padding:5px 12px;font-size:.8rem">Historia</a>
    <a href="/logout" class="btn btn-red" style="padding:5px 12px;font-size:.8rem">Wyloguj</a>
  </div>
</div>

<div class="content">

  <!-- FLASH -->
  {% for kat, wiad in komunikaty %}
  <div class="flash {{ 'flash-ok' if kat=='success' else 'flash-err' }}">{{ wiad }}</div>
  {% endfor %}

  <!-- KARTY: SECURITY + ENVIRONMENT -->
  <div class="cards-row">

    <!-- KARTA ANTYWLAMANIOWA -->
    <div class="card">
      <div class="card-title">Plytka antywlamaniowa (ESP32 #1)</div>
      {% if sec %}
        {% set st = sec.get('status','OFFLINE') %}
        <div class="field-row">
          <span class="field-label">Status alarmu</span>
          <span class="field-val
            {{ 's-alarm' if st=='ALARM'
               else 's-czuwa' if st in ('czuwa','OK','normalny')
               else 's-off' }}">
            {{ st | upper }}
          </span>
        </div>
        <div class="field-row">
          <span class="field-label">Czujnik PIR</span>
          <span class="field-val" style="color:{{ '#da3633' if sec.get('pir',0) else '#3fb950' }}">
            {{ 'WYKRYTO' if sec.get('pir',0) else 'spokój' }}
          </span>
        </div>
        <div class="field-row">
          <span class="field-label">Reed switch (drzwi/okno)</span>
          <span class="field-val" style="color:{{ '#da3633' if sec.get('drzwi',0) else '#3fb950' }}">
            {{ 'OTWARTE' if sec.get('drzwi',0) else 'zamknięte' }}
          </span>
        </div>
        <div class="field-row">
          <span class="field-label">Akcelerometr X / Y / Z</span>
          <span class="field-val mono">
            {{ '%.3f'|format(sec.get('acc_x',0.0)) }} &nbsp;
            {{ '%.3f'|format(sec.get('acc_y',0.0)) }} &nbsp;
            {{ '%.3f'|format(sec.get('acc_z',0.0)) }}
          </span>
        </div>
        <div class="field-row">
          <span class="field-label">Algorytm</span>
          <span class="field-val mono">{{ sec.get('uzyty_szyfr','—') }}</span>
        </div>
        <div class="field-row" style="border:none;margin-top:6px">
          <span class="field-label" style="font-size:.75rem">Hash SHA-256</span>
          <span class="mono" style="font-size:.72rem">{{ sec.get('data_hash','—')[:20] }}...</span>
        </div>
      {% else %}
        <p style="color:#6e7681;margin-top:12px">Brak danych z ostatniej godziny</p>
      {% endif %}
    </div>

    <!-- KARTA SRODOWISKOWA -->
    <div class="card">
      <div class="card-title">Plytka srodowiskowa (ESP32 #2)</div>
      {% if env %}
        <div class="field-row">
          <span class="field-label">Temperatura</span>
          <span class="field-val" style="color:#f0883e">
            {{ '%.1f'|format(env.get('temperatura',0.0)) }} °C
          </span>
        </div>
        <div class="field-row">
          <span class="field-label">Wilgotnosc</span>
          <span class="field-val">{{ '%.1f'|format(env.get('wilgotnosc',0.0)) }} %</span>
        </div>
        <div class="field-row">
          <span class="field-label">Cisnienie</span>
          <span class="field-val">{{ '%.1f'|format(env.get('cisnienie',0.0)) }} hPa</span>
        </div>
        <div class="field-row">
          <span class="field-label">Jakosc powietrza MQ135</span>
          <span class="field-val" style="color:{{ '#da3633' if env.get('gazy',0)>2000 else '#3fb950' }}">
            {{ '%d'|format(env.get('gazy',0)) }} / 4095
          </span>
        </div>
        <div class="field-row">
          <span class="field-label">Natezenie swiatla BH1750</span>
          <span class="field-val">{{ '%.1f'|format(env.get('swiatlo',0.0)) }} lx</span>
        </div>
        <div class="field-row">
          <span class="field-label">Dzwiek (mikrofon)</span>
          <span class="field-val" style="color:{{ '#da3633' if env.get('dzwiek',0) else '#c9d1d9' }}">
            {{ 'WYKRYTO' if env.get('dzwiek',0) else 'cisza' }}
          </span>
        </div>
        <div class="field-row">
          <span class="field-label">Algorytm</span>
          <span class="field-val mono">{{ env.get('uzyty_szyfr','—') }}</span>
        </div>
        <div class="field-row" style="border:none;margin-top:6px">
          <span class="field-label" style="font-size:.75rem">Hash SHA-256</span>
          <span class="mono" style="font-size:.72rem">{{ env.get('data_hash','—')[:20] }}...</span>
        </div>
      {% else %}
        <p style="color:#6e7681;margin-top:12px">Brak danych z ostatniej godziny</p>
      {% endif %}
    </div>
  </div><!-- /cards-row -->

  <!-- PANEL ZMIANY ALGORYTMU -->
  <div class="algo-panel">
    <span class="algo-label">Zmiana algorytmu</span>
    <form method="POST" action="/set_algorytm" style="display:flex;flex-wrap:wrap;gap:10px;align-items:center">
      <select name="board">
        <option value="antywlamaniowa">Plytka antywlamaniowa</option>
        <option value="srodowiskowa">Plytka srodowiskowa</option>
        <option value="obie">Obie plytki</option>
      </select>
      <select name="algorytm">
        {% for v, n in algory.items() %}
        <option value="{{ v }}">{{ n }}</option>
        {% endfor %}
      </select>
      <button type="submit" class="btn btn-green">Wyslij</button>
    </form>
  </div>

  <!-- TABELA HISTORII (ostatnia 1h) -->
  <div class="tbl-wrap">
    <div class="tbl-head">
      <span class="tbl-head-title">Historia pomiarow — ostatnia godzina</span>
      <a href="/historia" class="btn btn-blue" style="font-size:.8rem;padding:5px 12px">
        Pelna historia →
      </a>
    </div>
    <table>
      <thead>
        <tr>
          <th>Czas</th>
          <th>Plytka</th>
          <th>Dane / Status</th>
          <th>Algorytm</th>
          <th>Hash SHA-256</th>
          <th>TX Blockchain</th>
        </tr>
      </thead>
      <tbody>
      {% for r in historia %}
        {% if r.urzadzenie == 'security' %}
          {% set kls = 'tr-alarm' if r.status == 'ALARM' else 'tr-norm' %}
        {% else %}
          {% set kls = 'tr-env' %}
        {% endif %}
        <tr class="{{ kls }}">
          <td style="white-space:nowrap;color:#6e7681;font-size:.78rem">{{ r.czas }}</td>
          <td>
            {% if r.urzadzenie == 'security' %}
              <span style="color:#f0883e;font-weight:700;font-size:.8rem">Antywlamaniowa</span>
            {% else %}
              <span style="color:#388bfd;font-weight:700;font-size:.8rem">Srodowiskowa</span>
            {% endif %}
          </td>
          <td style="font-size:.8rem">
            {% if r.urzadzenie == 'security' %}
              <b style="color:{{ '#da3633' if r.status=='ALARM' else '#3fb950' }}">
                {{ r.status }}</b>
              &nbsp;Ruch: {{ 'wykryto' if r.pir else 'brak' }}
              &nbsp;Drzwi: {{ 'otwarte' if r.drzwi else 'zamkniete' }}
              &nbsp;Przysp. X/Y/Z: {{ '%.2f'|format(r.acc_x) }} /
              {{ '%.2f'|format(r.acc_y) }} /
              {{ '%.2f'|format(r.acc_z) }}
            {% else %}
              Temperatura: {{ '%.1f'|format(r.temperatura) }}°C
              &nbsp;Wilgotnosc: {{ '%.1f'|format(r.wilgotnosc) }}%
              &nbsp;Cisnienie: {{ '%.0f'|format(r.cisnienie) }}hPa
              &nbsp;Jakosc powietrza: {{ '%d'|format(r.gazy) }}
              &nbsp;Swiatlo: {{ '%.0f'|format(r.swiatlo) }}lx
              &nbsp;Dzwiek: {{ 'wykryto' if r.dzwiek else 'cisza' }}
            {% endif %}
          </td>
          <td><span class="mono">{{ r.uzyty_szyfr }}</span></td>
          <td><span class="mono" title="{{ r.data_hash }}">{{ r.data_hash[:12] }}...</span></td>
          <td>
            {% if r.tx_hash and r.tx_hash != '—' %}
              <span class="mono" title="{{ r.tx_hash }}" style="color:#3fb950">
                {{ r.tx_hash[:10] }}...
              </span>
            {% else %}
              <span style="color:#6e7681;font-size:.78rem">—</span>
            {% endif %}
          </td>
        </tr>
      {% else %}
        <tr><td colspan="6" style="text-align:center;color:#6e7681;padding:20px">
          Brak danych w ostatniej godzinie
        </td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

</div><!-- /content -->

<script>
let s = 5;
const el = document.getElementById('licz');
setInterval(() => { if (el && s > 0) el.textContent = --s; }, 1000);
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# SZABLON — DASHBOARD UZYTKOWNIKA (tylko raw payloady)
# ═══════════════════════════════════════════════════════════════════════════════
HTML_USER = """<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<title>Panel IoT — Zaszyfrowane dane</title>
<style>{{ css }}</style>
</head>
<body>
<div class="hdr">
  <div class="hdr-logo">System bezpieczenstwa IoT &nbsp;
    <span style="color:#6e7681;font-weight:400;font-size:.85rem">/ uzytkownik</span>
  </div>
  <div class="hdr-right">
    <span class="countdown">odswiezenie za <span id="licz">5</span>s</span>
    <a href="/logout" class="btn btn-red" style="padding:5px 12px;font-size:.8rem">Wyloguj</a>
  </div>
</div>
<div class="content">
  <div style="margin-bottom:16px">
    <h2 style="font-size:1rem;color:#8b949e;font-weight:600">
      Zaszyfrowane payloady — ostatnia godzina
    </h2>
    <p style="font-size:.8rem;color:#6e7681;margin-top:4px">
      Widok ograniczony. Dane wyswietlane w postaci zaszyfrowanej.
    </p>
  </div>
  <div class="raw-list">
  {% for item in payloady %}
    <div class="raw-item">
      <div class="raw-meta">
        <span>{{ item.czas }}</span>
        {% if item.urzadzenie == 'security' %}
          <span class="dev-s">Antywlamaniowa</span>
        {% else %}
          <span class="dev-e">Srodowiskowa</span>
        {% endif %}
      </div>
      <div class="raw-payload">{{ item.raw_enc }}</div>
    </div>
  {% else %}
    <p style="color:#6e7681;margin-top:20px">Brak danych w ostatniej godzinie.</p>
  {% endfor %}
  </div>
</div>
<script>
let s = 5;
const el = document.getElementById('licz');
setInterval(() => { if (el && s > 0) el.textContent = --s; }, 1000);
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# SZABLON — STRONA HISTORII (tylko admin)
# ═══════════════════════════════════════════════════════════════════════════════
HTML_HISTORIA = """<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>Historia — Panel Bezpieczenstwa IoT</title>
<style>{{ css }}</style>
</head>
<body>
<div class="hdr">
  <div class="hdr-logo">System bezpieczenstwa IoT &nbsp;
    <span style="color:#6e7681;font-weight:400;font-size:.85rem">/ historia</span>
  </div>
  <div class="hdr-right">
    <a href="/" class="btn btn-gray" style="padding:5px 12px;font-size:.8rem">← Dashboard</a>
    <a href="/logout" class="btn btn-red" style="padding:5px 12px;font-size:.8rem">Wyloguj</a>
  </div>
</div>
<div class="content">

  {% for kat, wiad in komunikaty %}
  <div class="flash {{ 'flash-ok' if kat=='success' else 'flash-err' }}">{{ wiad }}</div>
  {% endfor %}

  <!-- FILTR ZAKRESU DAT -->
  <div class="filter-bar">
    <span style="color:#58a6ff;font-weight:600;font-size:.9rem">Zakres dat</span>
    <form method="GET" action="/historia"
          style="display:flex;flex-wrap:wrap;gap:10px;align-items:center">
      <label style="font-size:.85rem;color:#8b949e">Od</label>
      <input type="datetime-local" name="od"
             value="{{ od_val }}" required>
      <label style="font-size:.85rem;color:#8b949e">Do</label>
      <input type="datetime-local" name="do"
             value="{{ do_val }}" required>
      <button type="submit" class="btn btn-blue">Szukaj</button>
    </form>
    <!-- Eksport CSV za wybrany zakres -->
    <form method="GET" action="/export_csv"
          style="display:flex;gap:10px;align-items:center">
      <input type="hidden" name="start" value="{{ od_val }}">
      <input type="hidden" name="stop"  value="{{ do_val }}">
      <button type="submit" class="btn btn-green">Eksportuj CSV</button>
    </form>
  </div>

  <!-- TABELA WYNIKOW -->
  <div class="tbl-wrap">
    <div class="tbl-head">
      <span class="tbl-head-title">
        Wyniki ({{ historia|length }} rekordow)
        {% if od_val and do_val %}
          &nbsp;<span style="color:#6e7681;font-size:.8rem">
            {{ od_val.replace('T',' ') }} — {{ do_val.replace('T',' ') }}
          </span>
        {% endif %}
      </span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Czas</th>
          <th>Plytka</th>
          <th>Status</th>
          <th>Ruch</th>
          <th>Drzwi</th>
          <th>Przysp. X/Y/Z</th>
          <th>Temperatura</th>
          <th>Wilgotnosc</th>
          <th>Cisnienie</th>
          <th>Jakosc powietrza</th>
          <th>Swiatlo</th>
          <th>Dzwiek</th>
          <th>Algorytm</th>
          <th>Hash</th>
          <th>TX Hash</th>
        </tr>
      </thead>
      <tbody>
      {% for r in historia %}
        {% if r.urzadzenie == 'security' %}
          {% set kls = 'tr-alarm' if r.status == 'ALARM' else 'tr-norm' %}
        {% else %}
          {% set kls = 'tr-env' %}
        {% endif %}
        <tr class="{{ kls }}">
          <td style="white-space:nowrap;color:#6e7681;font-size:.75rem">{{ r.czas }}</td>
          <td style="font-size:.78rem;font-weight:700;
            color:{{ '#f0883e' if r.urzadzenie=='security' else '#388bfd' }}">
            {{ 'Antywlamaniowa' if r.urzadzenie=='security' else 'Srodowiskowa' }}
          </td>
          <td style="font-weight:700;
            color:{{ '#da3633' if r.status=='ALARM' else '#3fb950' if r.urzadzenie=='security' else '#8b949e' }}">
            {{ r.status if r.urzadzenie=='security' else '—' }}
          </td>
          <td>{{ ('wykryto' if r.pir else 'brak') if r.urzadzenie=='security' else '—' }}</td>
          <td>{{ ('otwarte' if r.drzwi else 'zamkniete') if r.urzadzenie=='security' else '—' }}</td>
          <td class="mono">
            {% if r.urzadzenie=='security' %}
              {{ '%.2f'|format(r.acc_x) }}&nbsp;
              {{ '%.2f'|format(r.acc_y) }}&nbsp;
              {{ '%.2f'|format(r.acc_z) }}
            {% else %}—{% endif %}
          </td>
          <td>{{ '%.1f°C'|format(r.temperatura) if r.urzadzenie=='environment' else '—' }}</td>
          <td>{{ '%.1f%%'|format(r.wilgotnosc)  if r.urzadzenie=='environment' else '—' }}</td>
          <td>{{ '%.0fhPa'|format(r.cisnienie)  if r.urzadzenie=='environment' else '—' }}</td>
          <td>{{ '%d'|format(r.gazy)            if r.urzadzenie=='environment' else '—' }}</td>
          <td>{{ '%.0flx'|format(r.swiatlo)     if r.urzadzenie=='environment' else '—' }}</td>
          <td>{{ ('wykryto' if r.dzwiek else 'cisza') if r.urzadzenie=='environment' else '—' }}</td>
          <td><span class="mono">{{ r.uzyty_szyfr }}</span></td>
          <td><span class="mono" title="{{ r.data_hash }}">{{ r.data_hash[:12] }}...</span></td>
          <td>
            {% if r.tx_hash and r.tx_hash != '—' %}
              <span class="mono" style="color:#3fb950"
                    title="{{ r.tx_hash }}">{{ r.tx_hash[:10] }}...</span>
            {% else %}
              <span style="color:#6e7681">—</span>
            {% endif %}
          </td>
        </tr>
      {% else %}
        <tr><td colspan="15" style="text-align:center;color:#6e7681;padding:24px">
          Brak danych dla wybranego zakresu
        </td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERY SZABLONOW
# ═══════════════════════════════════════════════════════════════════════════════
def _render(szablon: str, **ctx):
    """Renderuje szablon z dolaczonym CSS i komunikatami flash."""
    ctx.setdefault("css", _CSS)
    ctx.setdefault("komunikaty", list(session.pop("_flashes", [])))
    return render_template_string(szablon, **ctx)


def _flash_pop() -> list:
    """Pobiera i usuwa komunikaty flash z sesji (kompatybilnosc z get_flashed_messages)."""
    from flask import get_flashed_messages
    return get_flashed_messages(with_categories=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TRASY FLASK
# ═══════════════════════════════════════════════════════════════════════════════

@aplikacja.route("/login", methods=["GET", "POST"])
def logowanie():
    if request.method == "POST":
        login = request.form.get("login", "").strip()
        haslo = request.form.get("haslo", "").strip()

        if login == "admin" and haslo == "admin":
            session["zalogowany"] = True
            session["rola"]       = "admin"
            session["login"]      = "admin"
            return redirect(url_for("panel"))

        if login == "user" and haslo == "user":
            session["zalogowany"] = True
            session["rola"]       = "user"
            session["login"]      = "user"
            return redirect(url_for("panel"))

        return render_template_string(HTML_LOGIN, css=_CSS,
                                      blad="Bledny login lub haslo")

    return render_template_string(HTML_LOGIN, css=_CSS, blad=None)


@aplikacja.route("/logout")
def wylogowanie():
    session.clear()
    return redirect(url_for("logowanie"))


@aplikacja.route("/")
@wymaga_logowania
def panel():
    rola = session.get("rola")

    if rola == "admin":
        sek_r  = pobierz_ostatni("security")
        env_r  = pobierz_ostatni("environment")
        sec    = _przetworz_rekord(sek_r) if sek_r else {}
        env    = _przetworz_rekord(env_r) if env_r else {}
        hist   = pobierz_historie("-1h", limit=50)
        sec_on = sprawdz_online("security")
        env_on = sprawdz_online("environment")
        komunikaty = _flash_pop()
        return render_template_string(
            HTML_ADMIN,
            css=_CSS,
            sec=sec,
            env=env,
            historia=hist,
            sec_online=sec_on,
            env_online=env_on,
            algory=NAZWY_ALGORYTMOW,
            komunikaty=komunikaty,
        )

    # Widok uzytkownika — tylko raw payloady
    payloady   = pobierz_raw_enc(limit=100)
    komunikaty = _flash_pop()
    return render_template_string(
        HTML_USER,
        css=_CSS,
        payloady=payloady,
        komunikaty=komunikaty,
    )


@aplikacja.route("/historia")
@wymaga_admina
def historia():
    od_val = request.args.get("od", "")
    do_val = request.args.get("do", "")
    dane   = []

    if od_val and do_val:
        try:
            start_rfc = _dt_local_do_rfc3339(od_val)
            stop_rfc  = _dt_local_do_rfc3339(do_val)
            dane      = pobierz_historie(start_rfc, stop_rfc, limit=500)
        except Exception as ex:
            flash(f"Blad zakresu dat: {ex}", "error")

    komunikaty = _flash_pop()
    return render_template_string(
        HTML_HISTORIA,
        css=_CSS,
        historia=dane,
        od_val=od_val,
        do_val=do_val,
        komunikaty=komunikaty,
    )


@aplikacja.route("/set_algorytm", methods=["POST"])
@wymaga_admina
def ustaw_algorytm():
    board  = request.form.get("board",     "").strip()
    algo   = request.form.get("algorytm",  "0").strip()

    if algo not in NAZWY_ALGORYTMOW:
        flash("Nieprawidlowy numer algorytmu (0–8)", "error")
        return redirect(url_for("panel"))

    topiki: list[str] = []
    if board in ("antywlamaniowa", "obie"):
        topiki.append(TOPIK_SET_SECURITY)
    if board in ("srodowiskowa", "obie"):
        topiki.append(TOPIK_SET_ENV)

    if not topiki:
        flash("Wybierz poprawna plytke", "error")
        return redirect(url_for("panel"))

    bledy: list[str] = []
    for topik in topiki:
        try:
            mqtt_publish.single(
                topik,
                payload=algo,
                hostname=MQTT_BROKER,
                port=1883,
                qos=1,
                retain=False,
            )
        except Exception as ex:
            bledy.append(f"{topik}: {ex}")

    if bledy:
        flash("Blad MQTT: " + "; ".join(bledy), "error")
    else:
        nazwa = NAZWY_ALGORYTMOW.get(algo, algo)
        cel   = {"antywlamaniowa": "Antywlamaniowej", "srodowiskowa": "Srodowiskowej",
                 "obie": "obu plytek"}.get(board, board)
        flash(f"Algorytm [{nazwa}] wysłany do {cel}", "success")

    return redirect(url_for("panel"))


@aplikacja.route("/export_csv")
@wymaga_admina
def eksportuj_csv():
    start_str = request.args.get("start", "").strip()
    stop_str  = request.args.get("stop",  "").strip()

    if not start_str or not stop_str:
        flash("Podaj zakres dat", "error")
        return redirect(url_for("historia"))

    try:
        start_rfc = _dt_local_do_rfc3339(start_str)
        stop_rfc  = _dt_local_do_rfc3339(stop_str)
        dane      = pobierz_historie(start_rfc, stop_rfc, limit=5000)
    except Exception as ex:
        flash(f"Blad eksportu: {ex}", "error")
        return redirect(url_for("historia"))

    buf     = io.StringIO()
    pisarz  = csv.writer(buf)
    pisarz.writerow([
        "Czas", "Urzadzenie",
        "Status", "PIR", "Drzwi", "Acc_X", "Acc_Y", "Acc_Z",
        "Temperatura", "Wilgotnosc", "Cisnienie", "Gazy", "Swiatlo", "Dzwiek",
        "Algorytm", "Hash_SHA256", "TX_Blockchain",
    ])
    for r in dane:
        pisarz.writerow([
            r["czas"],        r["urzadzenie"],
            r["status"],      r["pir"],         r["drzwi"],
            r["acc_x"],       r["acc_y"],        r["acc_z"],
            r["temperatura"], r["wilgotnosc"],   r["cisnienie"],
            r["gazy"],        r["swiatlo"],       r["dzwiek"],
            r["uzyty_szyfr"], r["data_hash"],     r["tx_hash"],
        ])

    nazwa_pliku = (f"iot_raport_{start_str[:10]}_do_{stop_str[:10]}.csv"
                   .replace(":", "-").replace(" ", "_"))
    odpowiedz = make_response(buf.getvalue())
    odpowiedz.headers["Content-Disposition"] = f"attachment; filename={nazwa_pliku}"
    odpowiedz.headers["Content-Type"] = "text/csv; charset=utf-8"
    return odpowiedz


# ═══════════════════════════════════════════════════════════════════════════════
# URUCHOMIENIE
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Wymaga cert.pem + key.pem w katalogu RPI/
    # Generowanie: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
    import os
    cert = os.path.join(os.path.dirname(__file__), "cert.pem")
    klucz = os.path.join(os.path.dirname(__file__), "key.pem")

    if os.path.exists(cert) and os.path.exists(klucz):
        ssl_ctx = (cert, klucz)
        print("[INFO] TLS wlaczone (cert.pem + key.pem)")
    else:
        ssl_ctx = None
        print("[WARN] Brak cert.pem/key.pem — uruchamiam bez TLS (HTTP)")

    aplikacja.run(host="0.0.0.0", port=5000, debug=False, ssl_context=ssl_ctx)
