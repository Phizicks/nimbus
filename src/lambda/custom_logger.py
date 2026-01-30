import logging
import os


class CustomFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\x1b[36;21m",  # grey
        logging.INFO: "\x1b[32;21m",  # green
        logging.WARNING: "\x1b[33;21m",  # yellow
        logging.ERROR: "\x1b[31;21m",  # red
        logging.CRITICAL: "\x1b[31;1m",  # bold red
    }
    RESET = "\x1b[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        fmt = "%(asctime)s.%(msecs)03d [%(levelname)s] %(module)s.%(funcName)s:%(lineno)d | %(message)s"
        formatter = logging.Formatter(fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())

# Parse LOG_LEVEL from environment variable
log_level_str = os.getenv("LOG_LEVEL", "DEBUG").upper()
log_level = getattr(logging, log_level_str, logging.INFO)  # fallback if invalid

root_logger = logging.getLogger()
root_logger.setLevel(log_level)
root_logger.handlers = [handler]

# shutup werkzeug
logging.getLogger("werkzeug").setLevel(logging.WARNING)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logging.getLogger("urllib3.poolmanager").setLevel(logging.WARNING)
logging.getLogger("urllib3.util.retry").setLevel(logging.WARNING)
