import logging
import socket
import ssl
import time

KIWI_HOST = "192.168.1.87"   # Your Kiwi Syslog Server IP
KIWI_PORT = 6514             # TLS port on Kiwi
CA_CERT = "KiwiCert.cer"     # Base-64 exported certificate from Kiwi

# --- SSL Setup ---
ssl_context = ssl.create_default_context(cafile=CA_CERT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_REQUIRED

sock = socket.create_connection((KIWI_HOST, KIWI_PORT))
tls_sock = ssl_context.wrap_socket(sock, server_hostname=KIWI_HOST)

# --- Custom Formatter with local RFC 5424 timestamp ---
class LocalTimeFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = time.localtime(record.created)
        if datefmt:
            return time.strftime(datefmt, ct)

        # RFC 5424: YYYY-MM-DDTHH:MM:SS±HH:MM
        t = time.strftime("%Y-%m-%dT%H:%M:%S", ct)

        tz_offset = -time.timezone  # seconds offset from UTC
        hours, remainder = divmod(abs(tz_offset), 3600)
        minutes = remainder // 60
        sign = "+" if tz_offset >= 0 else "-"

        return f"{t}{sign}{hours:02d}:{minutes:02d}"

# --- Custom TLS Syslog Handler ---
class TLSSysLogHandler(logging.Handler):
    # Syslog severity mapping
    SYSLOG_SEVERITY = {
        logging.CRITICAL: 2,
        logging.ERROR: 3,
        logging.WARNING: 4,
        logging.INFO: 6,
        logging.DEBUG: 7,
    }

    FACILITY = 16  # LOCAL0

    def __init__(self, tls_socket):
        super().__init__()
        self.tls_socket = tls_socket

    def emit(self, record):
        try:
            severity = self.SYSLOG_SEVERITY.get(record.levelno, 6)
            pri = self.FACILITY * 8 + severity  # PRI calculation

            message = self.format(record)
            syslog_msg = f"<{pri}>1 {message}\n"

            self.tls_socket.send(syslog_msg.encode())
        except Exception:
            self.handleError(record)


# --- Logger Setup ---
logger = logging.getLogger("my_app_logger")
logger.setLevel(logging.DEBUG)

handler = TLSSysLogHandler(tls_sock)
formatter = LocalTimeFormatter("%(asctime)s %(name)s %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# --- Send Test Messages ---
logger.info("This is an informational message sent over TLS Syslog.")
logger.warning("This is a WARNING message.")
logger.error("This is an ERROR message.")
logger.critical("This is a CRITICAL message.")

# --- Close TLS Socket ---
tls_sock.close()

