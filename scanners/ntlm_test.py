import requests

def check_ntlmv1(url):
    """
    Detecta si NTLMv1 está habilitado en un servidor de Active Directory.
    """
    headers = {
        'Authorization': 'NTLM ' + 'TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAA=='
    }
    response = requests.get(url, headers=headers, timeout=5)
    
    if 'NTLM' in response.headers.get('WWW-Authenticate', ''):
        return "NTLMv1 vulnerable"
    return "NTLMv1 no detectado"
