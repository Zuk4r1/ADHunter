import requests

def run_tests(url):
    results = []
    vulnerable_count = 0

    if "login" in url:
        results.append("[!] Posible LDAP Injection: Endpoint de login detectado.")
        vulnerable_count += 1

    if "/rpc" in url or "/ews" in url:
        results.append("[!] NTLM posible: Endpoint RPC/EWS puede aceptar autenticación NTLM.")
        vulnerable_count += 1

    if "/.env" in url or "/web.config" in url:
        results.append("[!] Archivo sensible posiblemente expuesto.")
        vulnerable_count += 1

    try:
        headers = {
            'Authorization': 'NTLM ' + 'TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAA=='
        }
        response = requests.get(url, headers=headers, timeout=5)
        if 'NTLM' in response.headers.get('WWW-Authenticate', ''):
            results.append("[!] NTLMv1 vulnerable: El servidor podría estar aceptando autenticación NTLMv1.")
            vulnerable_count += 1
    except Exception as e:
        results.append(f"[x] Error al verificar NTLMv1: {e}")

    try:
        response = requests.get(url + "/rpc", timeout=5)
        if "Microsoft" in response.text or "RPC" in response.text:
            results.append("[!] Posible Kerberoasting: Endpoint /rpc podría estar expuesto.")
            vulnerable_count += 1
    except Exception as e:
        results.append(f"[x] Error al verificar Kerberoasting: {e}")

    try:
        endpoints = ["/rpc", "/autodiscover/", "/owa"]
        exposed = []
        for ep in endpoints:
            r = requests.get(url + ep, timeout=5)
            if r.status_code == 200:
                exposed.append(ep)
        if exposed:
            results.append(f"[!] Endpoints expuestos: {', '.join(exposed)}")
            vulnerable_count += 1
    except Exception as e:
        results.append(f"[x] Error al verificar endpoints críticos: {e}")

    if not results:
        return {
            "vulnerabilities": [],
            "html_output": "No se detectaron problemas conocidos en los endpoints.",
            "vulnerable_count": 0,
            "safe_count": 1
        }

    return {
        "vulnerabilities": results,
        "html_output": "<br>".join(results),
        "vulnerable_count": vulnerable_count,
        "safe_count": max(1, 6 - vulnerable_count)
    }

def check_ntlmv1(url):
    try:
        headers = {
            'Authorization': 'NTLM ' + 'TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAA=='
        }
        response = requests.get(url, headers=headers, timeout=5)
        if 'NTLM' in response.headers.get('WWW-Authenticate', ''):
            return "[!] NTLMv1 vulnerable: El servidor podría estar aceptando autenticación NTLMv1."
    except Exception as e:
        return f"[x] Error al verificar NTLMv1: {e}"
    return "[OK] NTLMv1 no parece estar habilitado."

def check_kerberoasting(url):
    try:
        response = requests.get(url + "/rpc", timeout=5)
        if "Microsoft" in response.text or "RPC" in response.text:
            return "[!] Posible Kerberoasting: Endpoint /rpc podría estar expuesto."
    except Exception as e:
        return f"[x] Error al verificar Kerberoasting: {e}"
    return "[OK] No se detectaron indicios de Kerberoasting."

def check_exposed_endpoints(url):
    try:
        endpoints = ["/rpc", "/autodiscover/", "/owa"]
        exposed = []
        for ep in endpoints:
            r = requests.get(url + ep, timeout=5)
            if r.status_code == 200:
                exposed.append(ep)
        if exposed:
            return f"[!] Endpoints expuestos: {', '.join(exposed)}"
    except Exception as e:
        return f"[x] Error al verificar endpoints críticos: {e}"
    return "[OK] No se detectaron endpoints expuestos."
