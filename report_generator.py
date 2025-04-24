import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

REPORTS_DIR = "reports"
LATEST_REPORT_FILE = "latest_report.txt"

def generate_html_report(result_data, payloads=None):
    """
    Genera un reporte HTML a partir de los resultados y payloads utilizados.
    """
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reporte_{now}.html"
    filepath = os.path.join(REPORTS_DIR, filename)

    rendered_html = template.render(
        result=result_data,
        payloads=payloads or [],
        timestamp=now
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    # Guardamos el nombre del último reporte generado
    with open(LATEST_REPORT_FILE, "w") as f:
        f.write(filepath)

    return filepath
