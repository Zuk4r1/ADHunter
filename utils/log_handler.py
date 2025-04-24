import logging
import os
from datetime import datetime

class LogHandler:
    def __init__(self, log_dir="logs", log_level=logging.DEBUG):
        # Crear el directorio de logs si no existe
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Configuración básica del logger
        self.log_dir = log_dir
        self.log_level = log_level
        self.logger = logging.getLogger("ADHunterLogger")
        self.logger.setLevel(self.log_level)
        
        # Formato de los mensajes de log
        log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Crear archivo de log con nombre basado en la fecha
        log_filename = datetime.now().strftime('%Y-%m-%d') + ".log"
        log_path = os.path.join(self.log_dir, log_filename)
        
        # Manejador de archivo (para guardar logs en el archivo)
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(log_format)
        
        # Manejador de consola (para mostrar los logs en la consola)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_format)
        
        # Añadir los manejadores al logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log_info(self, message):
        """Registrar un mensaje de nivel INFO."""
        self.logger.info(message)
    
    def log_warning(self, message):
        """Registrar un mensaje de nivel WARNING."""
        self.logger.warning(message)
    
    def log_error(self, message):
        """Registrar un mensaje de nivel ERROR."""
        self.logger.error(message)
    
    def log_debug(self, message):
        """Registrar un mensaje de nivel DEBUG."""
        self.logger.debug(message)
    
    def log_exception(self, exception):
        """Registrar una excepción."""
        self.logger.exception(f"Exception: {exception}")
    
    def get_log_path(self):
        """Retorna la ruta del archivo de log actual."""
        log_filename = datetime.now().strftime('%Y-%m-%d') + ".log"
        return os.path.join(self.log_dir, log_filename)

# Ejemplo de uso:
if __name__ == "__main__":
    log_handler = LogHandler()

    # Registros de ejemplo
    log_handler.log_info("Inicio del escaneo de Active Directory.")
    log_handler.log_warning("Advertencia: Exposición de credenciales NTLMv1 detectada.")
    log_handler.log_error("Error al conectar con el servidor de Active Directory.")
    try:
        1 / 0  # Causar una excepción por ejemplo
    except Exception as e:
        log_handler.log_exception(e)
