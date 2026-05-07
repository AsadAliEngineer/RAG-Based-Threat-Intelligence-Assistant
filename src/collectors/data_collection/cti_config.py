from pathlib import Path
from config import Config
from typing import Tuple

class CTIConfig:
    """Handles configuration and path management for CTI conversion."""
    def __init__(self):
        self.config = Config()
        self.raw_cti_dir = self.config.cti_data_dir
        self.docs_cti_dir = self.config.cti_docs_dir
        self.logs_dir = self.config.logs_dir
        self.ensure_directories()

    def ensure_directories(self) -> None:
        """Ensure all necessary directories exist."""
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.docs_cti_dir.mkdir(parents=True, exist_ok=True)

    def get_paths(self) -> Tuple[Path, Path, Path]:
        """Return the main paths used in conversion."""
        return self.raw_cti_dir, self.docs_cti_dir, self.logs_dir 