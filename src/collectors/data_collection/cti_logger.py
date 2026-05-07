import logging
from pathlib import Path
from typing import Optional

def get_logger(log_file: Path) -> logging.Logger:
    """Set up and return a logger for CTI conversion."""
    logger = logging.getLogger('cti_conversion')
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        # File handler
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    logger.propagate = False
    return logger 