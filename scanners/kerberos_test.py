import requests

def check_kerberoasting(url):
    """
    Detecta si un endpoint es vulnerable a Kerberoasting (accounts con permisos de servicio).
    """
    response = requests.get(url + "/rpc", timeout=5)
    
    if "Microsoft" in response.text:  # Puede haber más pruebas dependiendo del servicio.
        return "Posible Kerberoasting detectado en el endpoint RPC"
    return "Kerberoasting no detectado"
