from flask import Flask, render_template, request
from utils.scanner import run_tests, check_ntlmv1, check_kerberoasting, check_exposed_endpoints
from report_generator import generate_html_report  # NUEVA LÍNEA IMPORTADA

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    vulnerable_count = 0  # Inicializamos el contador de vulnerabilidades
    safe_count = 0  # Inicializamos el contador de seguros

    if request.method == 'POST':
        url = request.form['url']
        
        # Ejecutamos las pruebas
        scan_data = run_tests(url)  # Ejecutamos la función de pruebas
        result = scan_data["html_output"]  # Obtenemos el resultado del escaneo

        # Actualizamos los contadores de vulnerabilidades y seguros
        vulnerable_count = scan_data["vulnerable_count"]
        safe_count = scan_data["safe_count"]
        
        # Añadimos las nuevas pruebas
        result += "\n" + check_ntlmv1(url)
        result += "\n" + check_kerberoasting(url)
        result += "\n" + check_exposed_endpoints(url)

        # Generación del reporte HTML
        payloads_info = [
    {
        "nombre": "Prueba XSS Reflejado",
        "payload": "<script>alert('XSS')</script>",
        "impacto": "Permite la ejecución de scripts maliciosos en el navegador de la víctima.",
        "comando": "GET /vulnerable?input=<script>alert('XSS')</script>"
    },
    {
        "nombre": "Inyección SQL",
        "payload": "' OR '1'='1",
        "impacto": "Permite evadir autenticación y acceder a datos sensibles.",
        "comando": "POST /login -d \"username=admin&password=' OR '1'='1\""
    }
]

	generate_html_report(result_data=result, payloads=payloads_info)

    return render_template("index.html", result=result, 
                           vulnerable_count=vulnerable_count, 
                           safe_count=safe_count)  # Pasamos los contadores a la plantilla

if __name__ == '__main__':
    app.run(debug=True)
