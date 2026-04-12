from flask import Flask, render_template_string, request, session, redirect, url_for
from influxdb_client import InfluxDBClient
import pytz
import hashlib
from collections import defaultdict
import os

app = Flask(__name__)
# klucz potrzebny do szyfrowania ciasteczek sesji we flasku
app.secret_key = "" 

INFLUX_TOKEN = ""
INFLUX_ORG = ""
INFLUX_BUCKET = "dane_esp"
INFLUX_URL = "http://localhost:8086"

client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)

# widok logowania
HTML_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Logowanie</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #eef2f3; height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; width: 300px; }
        h2 { color: #2c3e50; margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 90%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }
        .btn-login { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-size: 16px; margin-top: 10px; }
        .btn-login:hover { background: #2980b9; }
        .error { color: #e74c3c; font-size: 0.9em; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Logowanie do panelu</h2>
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Login" required>
            <input type="password" name="password" placeholder="Haslo" required>
            <button type="submit" class="btn-login">Zaloguj</button>
        </form>
    </div>
</body>
</html>
"""

# glowny szablon po zalogowaniu
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Panel IoT - Magisterka</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #eef2f3; padding: 20px; color: #333; }
        .container { max-width: 1100px; margin: auto; background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); overflow: hidden; }
        .header { background: #2c3e50; color: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; }
        .header h2 { margin: 0; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 12px; border-bottom: 1px solid #eee; }
        .data-row { background: #fff; font-weight: bold; }
        .data-row:hover { background: #f9f9f9; }
        .hash-row { background: #f8f9fa; border-bottom: 2px solid #ddd; font-family: monospace; font-size: 0.85em; color: #555; }
        .btn-verify { background: #27ae60; color: white; padding: 5px 15px; border: none; border-radius: 4px; cursor: pointer; float: right; text-decoration: none;}
        .btn-verify:hover { background: #219653; }
        .btn-logout { background: #e74c3c; color: white; padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-weight: bold;}
        .btn-logout:hover { background: #c0392b; }
        .hash-display { display: none; color: #d35400; font-weight: bold; margin-top: 5px;}
        .string-display { color: #7f8c8d; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Dane z czujnikow i weryfikacja (hash)</h2>
            <a href="/logout" class="btn-logout">Wyloguj</a>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Czas</th>
                    <th>Temperatura</th>
                    <th>Wilgotnosc</th>
                    <th>Cisnienie</th>
                    <th>Gazy</th>
                    <th>Swiatlo</th>
                    <th>Dzwiek</th>
                </tr>
            </thead>
            <tbody>
                {% for time, sensors in grouped_data.items() %}
                <tr class="data-row">
                    <td>{{ time }}</td>
                    <td>{{ sensors.get('temperatura', '-') }}</td>
                    <td>{{ sensors.get('wilgotnosc', '-') }}</td>
                    <td>{{ sensors.get('cisnienie', '-') }}</td>
                    <td>{{ sensors.get('gazy', '-') }}</td>
                    <td>{{ sensors.get('swiatlo', '-') }}</td>
                    <td>{{ sensors.get('dzwiek', '-') }}</td>
                </tr>
                <tr class="hash-row">
                    <td colspan="7">
                        <button class="btn-verify" onclick="document.getElementById('hash-{{ loop.index }}').style.display='block'">Sprawdz Hash (SHA-256)</button>
                        <div id="hash-{{ loop.index }}" class="hash-display">
                            <div class="string-display">Dane wejsciowe: {{ sensors.data_string }}</div>
                            WYNIKOWY HASH: {{ sensors.row_hash }}
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # login i haslo ustawione na sztywno
        if request.form['username'] == 'admin' and request.form['password'] == 'admin':
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = 'Zly login lub haslo.'
    
    return render_template_string(HTML_LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None) # ubicie sesji
    return redirect(url_for('login'))

@app.route('/')
def index():
    # wywala do logowania jesli brak sesji
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # pobieranie danych z ostatniej godziny
    query = f'from(bucket: "{INFLUX_BUCKET}") |> range(start: -1h)'
    tables = client.query_api().query(query, org=INFLUX_ORG)
    
    grouped_data = defaultdict(dict)
    warsaw_tz = pytz.timezone('Europe/Warsaw')

    # parsowanie tego co zwroci influx
    for table in tables:
        for r in table.records:
            time_str = r.get_time().astimezone(warsaw_tz).strftime("%H:%M:%S")
            sensor = r.values.get("sensor")
            val = r.get_value()
            grouped_data[time_str][sensor] = val

    # wyliczanie hashy dla kazdego wiersza
    for time_str, sensors in grouped_data.items():
        t = sensors.get('temperatura', 0)
        w = sensors.get('wilgotnosc', 0)
        c = sensors.get('cisnienie', 0)
        g = sensors.get('gazy', 0)
        s = sensors.get('swiatlo', 0)
        d = sensors.get('dzwiek', 0)

        # format taki sam jak przy kotwiczeniu w blockchainie
        data_string = f"T:{t}|W:{w}|C:{c}|G:{g}|S:{s}|D:{d}"
        row_hash = hashlib.sha256(data_string.encode()).hexdigest()

        sensors['data_string'] = data_string
        sensors['row_hash'] = row_hash

    # sortowanie zeby najnowsze byly na gorze
    sorted_data = dict(sorted(grouped_data.items(), reverse=True))

    return render_template_string(HTML_TEMPLATE, grouped_data=sorted_data)

if __name__ == '__main__':
    # odpalenie serwera webowego na https 
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=('cert.pem', 'key.pem'))