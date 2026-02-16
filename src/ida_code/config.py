import os
from pathlib import Path

IDA_INSTALL_DIR = Path(os.environ.get("IDA_INSTALL_DIR", "/opt/ida-pro-9.2"))
IDA_DOCS_DIR = IDA_INSTALL_DIR / "docs"
IDA_PYTHON_DIR = IDA_INSTALL_DIR / "python"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING").upper()
