import requests

def check_exposed_endpoints(url):
    """
    Comprueba si hay endpoints críticos de Active Directory expuestos.
    """
    endpoints = ['/rpc', '/autodiscover/', '/owa']
    exposed_endpoints = []
    
    for endpoint in endpoints:
        response = requests.get(url + endpoint, timeout=5)
        if response.status_code == 200:
            exposed_endpoints.append(endpoint)
    
    if exposed_endpoints:
        return f"Endpoints expuestos: {', '.join(exposed_endpoints)}"
    return "No se detectaron endpoints críticos expuestos"
