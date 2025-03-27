from flask import Flask, request, render_template_string, Response
import socket
import time

app = Flask(__name__)

def scan_port(ip, port, timeout=1):
    """
    Tente de se connecter au port donné sur l'IP et renvoie True si le port est ouvert.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def generate_scan_stream(ips):
    """
    Génère des messages en continu (SSE) pendant le scan et, à la fin,
    envoie un résumé final basé sur les sorties [OPEN].
    """
    camera_ports = [80, 443, 554, 8000, 8080, 8554]
    final_summary = []  # Stocke les lignes avec [OPEN]

    for ip in ips:
        yield f"data: [IP] Scanning {ip}...\n\n"
        time.sleep(0.5)
        ip_has_open = False
        for port in camera_ports:
            yield f"data: Scanning port {port} on {ip}...\n\n"
            time.sleep(0.5)
            if scan_port(ip, port):
                open_line = f"[OPEN] Found open port {port} on {ip}"
                yield f"data: {open_line}\n\n"
                final_summary.append(open_line)
                ip_has_open = True
        if not ip_has_open:
            yield f"data: [INFO] No open ports found on {ip}\n\n"
        yield "data: ---------------------\n\n"
    
    yield "data: Scan terminé\n\n"
    
    # Construction du résumé final
    summary_text = "Final Summary:\n"
    if final_summary:
        summary_text += "\n".join(final_summary)
    else:
        summary_text += "Aucun port ouvert trouvé sur aucune IP."
    
    yield f"data: {summary_text}\n\n"
    yield "data: FIN\n\n"

@app.route('/')
def index():
    # Page d'accueil avec disclaimer et interface embelli
    return render_template_string('''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Scan Ouverture de Port</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f4f9;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: auto;
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            text-align: center;
            color: #333;
        }
        .disclaimer {
            font-size: 0.8em;
            color: #777;
            margin-bottom: 20px;
            border: 1px solid #ccc;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        form label {
            display: block;
            margin-bottom: 5px;
        }
        textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        button {
            background-color: #007BFF;
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>Scan Ouverture de Port</h1>
    <div class="disclaimer">
        <p><strong>Avertissement :</strong> Ce site est fourni à des fins éducatives et de test uniquement. Toute utilisation de cet outil à des fins illégales relève de la seule responsabilité de l'utilisateur. L'auteur décline toute responsabilité en cas d'usage inapproprié.</p>
    </div>
    <form action="/scan" method="post">
        <label for="ips">Entrez les adresses IP (une par ligne) :</label>
        <textarea id="ips" name="ips" rows="10" cols="50"></textarea>
        <br><br>
        <button type="submit">Lancer le scan</button>
    </form>
</div>
</body>
</html>
''')

@app.route('/scan', methods=['POST'])
def scan():
    ips_text = request.form.get('ips', '')
    ips = [line.strip() for line in ips_text.splitlines() if line.strip()]
    ips_query = ",".join(ips)
    return render_template_string('''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Progression du Scan - Scan Ouverture de Port</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f4f9;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: auto;
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            text-align: center;
            color: #333;
        }
        #log {
            background-color: #e9ecef;
            padding: 10px;
            white-space: pre-wrap;
            font-family: monospace;
            border-radius: 4px;
            height: 400px;
            overflow-y: auto;
        }
        a {
            display: inline-block;
            margin-top: 20px;
            text-decoration: none;
            color: #007BFF;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>Progression du Scan - Scan Ouverture de Port</h1>
    <div id="log"></div>
    <script>
        var source = new EventSource("/scan_stream?ips={{ ips_query }}");
        source.onmessage = function(event) {
            var log = document.getElementById("log");
            var p = document.createElement("p");
            if(event.data.indexOf("[OPEN]") !== -1) {
                p.innerHTML = "<span style='color: green; font-weight: bold;'>" + event.data + "</span>";
            } else {
                p.textContent = event.data;
            }
            log.appendChild(p);
            log.scrollTop = log.scrollHeight;
            if(event.data.indexOf("FIN") !== -1){
                source.close();
            }
        };
        source.onerror = function(event) {
            console.error("Erreur dans la connexion SSE", event);
            source.close();
        };
    </script>
    <a href="/">Retour</a>
</div>
</body>
</html>
''', ips_query=ips_query)

@app.route('/scan_stream')
def scan_stream():
    ips_param = request.args.get('ips', '')
    ips = ips_param.split(",") if ips_param else []
    return Response(generate_scan_stream(ips), mimetype='text/event-stream')

if __name__ == "__main__":
    app.run(debug=True)
