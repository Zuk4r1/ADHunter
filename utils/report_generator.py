import os
from datetime import datetime
from tabulate import tabulate

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        # Crear el directorio para los informes si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        self.output_dir = output_dir
        self.date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.report_file = os.path.join(self.output_dir, f"report_{self.date}.html")
    
    def generate_html_report(self, results, vulnerable_count, safe_count):
        """Generar informe HTML a partir de los resultados del escaneo."""
        html_content = f"""
        <html>
        <head>
            <title>Informe de Escaneo - ADOwner</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    color: #333;
                }}
                h1 {{
                    color: #3f51b5;
                    text-align: center;
                }}
                .summary {{
                    font-size: 1.2em;
                    margin-bottom: 20px;
                }}
                .results {{
                    margin-top: 20px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th, td {{
                    padding: 8px;
                    border: 1px solid #ddd;
                    text-align: left;
                }}
                th {{
                    background-color: #3f51b5;
                    color: white;
                }}
                .vulnerable {{
                    background-color: #ffebee;
                }}
                .safe {{
                    background-color: #e8f5e9;
                }}
            </style>
        </head>
        <body>
            <h1>Informe de Escaneo de Active Directory</h1>
            <div class="summary">
                <p><strong>Total de vulnerabilidades:</strong> {vulnerable_count}</p>
                <p><strong>Total de sistemas seguros:</strong> {safe_count}</p>
            </div>
            <div class="results">
                <h2>Resultados del Escaneo:</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Vulnerabilidad</th>
                            <th>Estado</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        # Generamos las filas de los resultados
        for result in results.split('<br>'):
            status = 'Seguro' if '[!]' not in result else 'Vulnerable'
            row_class = 'safe' if status == 'Seguro' else 'vulnerable'
            html_content += f"""
                <tr class="{row_class}">
                    <td>{result}</td>
                    <td>{status}</td>
                </tr>
            """
        
        # Cerrar el HTML
        html_content += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        
        # Guardar el archivo HTML
        with open(self.report_file, 'w') as file:
            file.write(html_content)
        
        return self.report_file
    
    def generate_markdown_report(self, results, vulnerable_count, safe_count):
        """Generar informe en formato Markdown."""
        markdown_content = f"""
# Informe de Escaneo de Active Directory

**Total de vulnerabilidades**: {vulnerable_count}  
**Total de sistemas seguros**: {safe_count}

## Resultados del Escaneo:

| Vulnerabilidad | Estado |
|----------------|--------|
"""
        
        # Agregar los resultados en formato tabla
        for result in results.split('<br>'):
            status = 'Seguro' if '[!]' not in result else 'Vulnerable'
            markdown_content += f"| {result} | {status} |\n"
        
        # Guardar el archivo Markdown
        markdown_filename = os.path.join(self.output_dir, f"report_{self.date}.md")
        with open(markdown_filename, 'w') as file:
            file.write(markdown_content)
        
        return markdown_filename
    
    def get_report_file(self):
        """Retorna la ruta del archivo de informe generado."""
        return self.report_file


# Ejemplo de uso
if __name__ == "__main__":
    # Datos de ejemplo (esto sería lo generado por el escaneo)
    scan_results = "admin)(userPassword=*)(|(mail=*))<br>admin'*)(uid=*))<br>userPassword=*(|<br>"
    vulnerable_count = 3
    safe_count = 2
    
    # Crear instancia del generador de informes
    report_generator = ReportGenerator()

    # Generar informe HTML
    html_report = report_generator.generate_html_report(scan_results, vulnerable_count, safe_count)
    print(f"Informe HTML generado: {html_report}")

    # Generar informe Markdown
    markdown_report = report_generator.generate_markdown_report(scan_results, vulnerable_count, safe_count)
    print(f"Informe Markdown generado: {markdown_report}")
