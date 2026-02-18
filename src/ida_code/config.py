import os
from pathlib import Path

IDA_INSTALL_DIR = Path(os.environ.get("IDA_INSTALL_DIR", "/opt/ida-pro-9.2"))
IDA_DOCS_DIR = IDA_INSTALL_DIR / "docs"
IDA_PYTHON_DIR = IDA_INSTALL_DIR / "python"
IDA_EXAMPLES_DIR = IDA_PYTHON_DIR / "examples"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING").upper()
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
