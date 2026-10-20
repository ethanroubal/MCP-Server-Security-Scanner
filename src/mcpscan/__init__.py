"""mcpscan: security scanner for Model Context Protocol servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcpscan")
except PackageNotFoundError:  # running from a source checkout without installing
    __version__ = "0.0.0+unknown"
