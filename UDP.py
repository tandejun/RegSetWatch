import logging
import logging.handlers

logger = logging.getLogger('my_app_logger')
logger.setLevel(logging.INFO)  # Set the minimum logging level

# For UDP (default Syslog port 514)
syslog_handler = logging.handlers.SysLogHandler(address=('192.168.1.87', 514))

logger.addHandler(syslog_handler)
logger.info("This is an informational message sent to Syslog as a test.")
logger.warning("A warning occurred in the application.")
logger.error("An error happened!")