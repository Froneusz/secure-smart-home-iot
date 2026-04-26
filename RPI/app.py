from flask import Flask, render_template_string, request, session, redirect, url_for, make_response
from influxdb_client import InfluxDBClient
import pytz, hashlib, io, csv
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)
app.secret_key = "" #klucz szyfrowania ciasteczek sesyjnych

INFLUX_TOKEN = "" #klucz API bazy 
INFLUX_ORG = ""
INFLUX_BUCKET = ""
INFLUX_URL = ""

client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG) #inicjalizacja polaczenia z influxdb

#szablon html glownego panelu z uzyciem jinja2
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Panel IoT - Magisterka</title>
    <meta http-equiv="refresh" content="10"> <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #eef2f3; padding: 20px; color: #333; }
        .container { max-width: 1400px; margin: auto; background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); overflow: hidden; }
        .header { background: #2c3e50; color: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; }
        .badge { padding: 8px 15px; border-radius: 20px; font-weight: bold; color: white; font-size: 0.9em; margin-right: 10px;}
        .badge-on { background: #27ae60; } .badge-off { background: #e74c3c; }
        .export-section { background: #f1f4f6; padding: 20px; border-bottom: 2px solid #ddd; display: flex; align-items: center; gap: 20px; }
        .btn-download { background: #f39c12; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;}
        table { width: 100%; border-collapse: collapse; text-align: center; font-size: 0.95em; table-layout: fixed;}
        th { background: #34495e; color: white; padding: 12px; }
        td { padding: 10px; border-bottom: 1px solid #eee; word-wrap: break-word;}
        .btn-logout { background: #c0392b; color: white; padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none;}
        .acc-data { font-size: 0.85em; color: #444; font-weight: bold;}
        .crypto-block { font-family: monospace; font-size: 0.85em; color: #8e44ad; background: #f9f2fd; padding: 5px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Live Monitor (Rola: {{ session.role | upper }})</h2> <div style="display: flex; align-items: center;">
                <div class="badge {% if sec_online %}badge-on{% else %}badge-off{% endif %}">Alarm: {{ 'ONLINE' if sec_online else 'OFFLINE' }}</div>
                <div class="badge {% if env_online %}badge-on{% else %}badge-off{% endif %}">Środowisko: {{ 'ONLINE' if env_online else 'OFFLINE' }}</div>
                <a href="/logout" class="btn-logout">Wyloguj</a>
            </div>
        </div>
        <div class="export-section">
            <form action="/export_csv" method="GET" style="display: flex; align-items: center; gap: 15px;">
                <label>Archiwum (CSV): Od</label>
                <input type="datetime-local" name="start" required> <label>Do</label> <input type="datetime-local" name="stop" required>
                <button type="submit" class="btn-download">Pobierz Dane</button>
            </form>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 10%;">Czas</th>
                    {% if session.role == 'admin' %} <th style="width: 15%;">Status</th>
                        <th style="width: 10%;">PIR/Drzwi</th>
                        <th style="width: 25%;">Akcelerometr (X, Y, Z)</th>
                        <th style="width: 15%;">Temp/Wilg</th>
                        <th style="width: 25%;">Blockchain Hash</th>
                    {% else %}
                        <th style="width: 90%;" colspan="5">Dane Zaszyfrowane</th>
                    {% endif %}
                </tr>
            </thead>
            <tbody>
                {% for row in data_list %} <tr>
                    <td>{{ row.time }}</td>
                    {% if session.role == 'admin' %}
                        <td style="color: {% if row.status == 'ALARM' %}red{% elif row.status == 'czuwa' %}green{% else %}blue{% endif %}; font-weight: bold;">{{ row.status|upper }}</td>
                        <td>{{ row.pir }} / {{ row.drzwi }}</td>
                        <td class="acc-data">X: {{ "%.2f"|format(row.acc_x) }} | Y: {{ "%.2f"|format(row.acc_y) }} | Z: {{ "%.2f"|format(row.acc_z) }}</td>
                        <td>{{ row.temp }}°C / {{ row.wilg }}%</td>
                        <td style="font-size: 0.8em; color: #7f8c8d;">{{ row.hash[:16] }}...</td>
                    {% else %}
                        <td colspan="5"><div class="crypto-block">{{ row.raw_enc }}</div></td> {% endif %}
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

#szablon html panelu logowania
HTML_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Logowanie</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #eef2f3; height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; width: 300px; }
        h2 { color: #2c3e50; margin-bottom: 20px; }
        input { width: 90%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }
        .btn-login { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-size: 16px; margin-top: 10px; }
        .info { font-size: 0.8em; color: #7f8c8d; margin-top: 15px;}
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Panel Magisterski</h2>
        {% if error %}<div style="color:red; margin-bottom:10px;">{{ error }}</div>{% endif %} <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Login" required>
            <input type="password" name="password" placeholder="Haslo" required>
            <button type="submit" class="btn-login">Zaloguj</button>
        </form>
        <div class="info">Zaloguj jako <b>login</b>:login (widok szyfrowany)<br>lub <b>admin</b>:admin (pełny dostęp)</div>
    </div>
</body>
</html>
"""

def pobierz_dane_z_influx(query, format_czasu="%H:%M:%S"):
    tables = client.query_api().query(query, org=INFLUX_ORG) #wykonanie zapytania flux do bazy
    grouped_data = defaultdict(lambda: {"sec": {}, "env": {}}) #inicjalizacja struktury na dane zgrupowane po czasie
    warsaw_tz = pytz.timezone('Europe/Warsaw')
    
    for table in tables:
        for r in table.records:
            time_str = r.get_time().astimezone(warsaw_tz).strftime(format_czasu) #konwersja czasu utc do strefy lokalnej
            urzadzenie = r.values.get("urzadzenie")
            sensor = r.values.get("sensor")
            val = r.get_value() #pobranie wartosci uniezaleznione od f_val/s_val
            
            if urzadzenie == "security": grouped_data[time_str]["sec"][sensor] = val
            else: grouped_data[time_str]["env"][sensor] = val

    processed_data = {}
    for time_str, d in grouped_data.items():
        s = d["sec"]; e = d["env"]
        
        def safe_f(v): #bezpieczne rzutowanie na float z obsluga brakow
            try: return float(v)
            except: return 0.0

        status = str(s.get('status', 'OFFLINE'))
        pir, drzwi = int(safe_f(s.get('pir', 0))), int(safe_f(s.get('drzwi', 0)))
        ax, ay, az = safe_f(s.get('acc_x', 0)), safe_f(s.get('acc_y', 0)), safe_f(s.get('acc_z', 0))
        
        #rekonstrukcja stringa zrodlowego do obliczenia hasha
        data_string = f"S:[{status}|{pir}|{drzwi}|{round(ax,2)}|{round(ay,2)}|{round(az,2)}]|E:[{e.get('temperatura','OFFLINE')}|{e.get('wilgotnosc','-')}|0|0|0|0]"
        
        processed_data[time_str] = {
            "time": time_str, "status": status, "pir": pir, "drzwi": drzwi,
            "acc_x": ax, "acc_y": ay, "acc_z": az,
            "temp": e.get('temperatura', '-'), "wilg": e.get('wilgotnosc', '-'),
            "raw_enc": s.get('raw_enc', 'System oczekuje na dane...'),
            "hash": hashlib.sha256(data_string.encode()).hexdigest() #obliczanie i dolaczanie hasha sha256
        }
    return dict(sorted(processed_data.items(), reverse=True)) #zwracanie danych posortowanych malejaco wg czasu

@app.route('/export_csv')
def export_csv():
    if not session.get('logged_in'): return redirect(url_for('login')) #blokada dla niezalogowanych
    if session.get('role') != 'admin': return "Błąd: Brak uprawnień do eksportu danych.", 403 #RBAC - blokada dla userow
    
    start_raw = request.args.get('start')
    stop_raw = request.args.get('stop')
    if not start_raw or not stop_raw: return "Wybierz daty!", 400

    try:
        warsaw_tz = pytz.timezone('Europe/Warsaw')
        #konwersja czasu wejsciowego z kalendarza do formatu iso wymaganego przez influxdb
        start_iso = warsaw_tz.localize(datetime.strptime(start_raw, "%Y-%m-%dT%H:%M")).astimezone(pytz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        stop_iso = warsaw_tz.localize(datetime.strptime(stop_raw, "%Y-%m-%dT%H:%M")).astimezone(pytz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        query = f'from(bucket:"{INFLUX_BUCKET}") |> range(start:{start_iso}, stop:{stop_iso}) |> filter(fn:(r)=>r._measurement=="pomiary_srodowiskowe")'
        data = pobierz_dane_z_influx(query, "%Y-%m-%d %H:%M:%S")
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Czas', 'Status', 'PIR', 'Drzwi', 'Acc_X', 'Acc_Y', 'Acc_Z', 'Temp', 'Wilg', 'HASH_BLOCKCHAIN']) #zapis naglowkow csv
        for r in data.values():
            writer.writerow([r['time'], r['status'], r['pir'], r['drzwi'], r['acc_x'], r['acc_y'], r['acc_z'], r['temp'], r['wilg'], r['hash']])
        
        res = make_response(output.getvalue())
        res.headers["Content-Disposition"] = f"attachment; filename=raport_iot.csv" #wymuszenie pobierania pliku przez przegladarke
        res.headers["Content-type"] = "text/csv"
        return res
    except Exception as e: return f"Błąd eksportu: {e}", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']
        if u == 'admin' and p == 'admin': #prosta autentykacja dla admina
            session['logged_in'] = True; session['role'] = 'admin'; return redirect(url_for('index'))
        if u == 'login' and p == 'login': #prosta autentykacja dla uzytkownika (tylko odczyt raw)
            session['logged_in'] = True; session['role'] = 'user'; return redirect(url_for('index'))
        return render_template_string(HTML_LOGIN_TEMPLATE, error="Zły login/hasło")
    return render_template_string(HTML_LOGIN_TEMPLATE)

@app.route('/logout')
def logout(): 
    session.clear() #czyszczenie calej sesji
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'): return redirect(url_for('login'))
    
    query = f'from(bucket:"{INFLUX_BUCKET}") |> range(start: -1h) |> filter(fn:(r)=>r._measurement=="pomiary_srodowiskowe")' #pobieranie danych tylko z ostatniej godziny
    data = pobierz_dane_z_influx(query, "%H:%M:%S")
    
    #dynamiczne wykrywanie aktywnosci urzadzen dla badge
    sec_on = any(r['status'] != 'OFFLINE' for r in data.values()) if data else False
    
    return render_template_string(HTML_TEMPLATE, data_list=list(data.values()), sec_online=sec_on, env_online=False)

if __name__ == '__main__':
    #uruchamianie serwera produkcyjnego flask z certyfikatami tls/ssl
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=('cert.pem', 'key.pem'))