import requests

def check_ntlm_auth(url):
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/122.0.0.0 Safari/537.36'
        ),
        'Accept': '*/*',
        'Connection': 'close'
    }

    try:
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=7, verify=True)
        www_auth = response.headers.get("WWW-Authenticate", "")

        # Normalizamos la cabecera para evitar falsos negativos
        www_auth_normalized = www_auth.upper().replace(" ", "")
        
        if "NTLM" in www_auth_normalized:
            return f"[!] NTLM detectado en {url}: el encabezado WWW-Authenticate contiene 'NTLM'."
        elif "NEGOTIATE" in www_auth_normalized or "BASIC" in www_auth_normalized:
            return f"[!] Autenticación detectada (posiblemente NTLM/Kerberos/Basic) en {url}: {www_auth}"
        elif www_auth:
            return f"[~] Encabezado WWW-Authenticate presente pero no contiene NTLM: {www_auth}"
        else:
            return f"[-] No se detectó autenticación NTLM en {url}."

    except requests.exceptions.SSLError:
        return f"[ERROR] Error SSL al conectar con {url}. Puede requerir un certificado válido o configuración específica."
    except requests.exceptions.Timeout:
        return f"[ERROR] Timeout al intentar conectar con {url}."
    except requests.exceptions.ConnectionError as e:
        return f"[ERROR] Error de conexión a {url}: {str(e)}"
    except requests.exceptions.RequestException as e:
        return f"[ERROR] No se pudo conectar a {url}: {str(e)}"

# Uso de ejemplo
if __name__ == "__main__":
    target = input("Introduce la URL a probar (ej: http://target.com/rpc): ").strip()
    result = check_ntlm_auth(target)
    print(result)

