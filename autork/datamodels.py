# autork/datamodels.py
from dataclasses import dataclass, field
from typing import Optional, List, Dict

@dataclass
class Service:
    """
    Represents a network service identified on a port.
    """
    name: str = ""
    version: str = ""
    product: str = ""
    extrainfo: str = ""
    ostype: str = ""
    method: str = ""
    conf: int = 0

@dataclass
class Port:
    """
    Represents a network port on a host.
    """
    number: int
    protocol: str = "tcp"
    status: str = "unknown"
    service: Optional[Service] = None
    reason: str = ""
    # reason_ttl: int = 0 # Optional: can be added if needed
    scripts: Optional[Dict[str, str]] = None # NEW: Stores NSE script results {script_id: output}

@dataclass
class OSMatch:
    """
    Represents an OS match identified by Nmap.
    """
    name: str = ""
    accuracy: int = 0
    line: int = 0 # Optional: Nmap OS DB line number for the match

@dataclass
class Host:
    """ Represents a target host and its gathered reconnaissance information. """
    ip: str
    hostname: Optional[str] = None
    status: str = "unknown"
    ports: List[Port] = field(default_factory=list)
    os_matches: List[OSMatch] = field(default_factory=list)
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    uptime_seconds: Optional[int] = None
    last_boot: Optional[str] = None
    distance: Optional[int] = None
    host_scripts: Optional[Dict[str, str]] = None # NEW: Stores NSE host script results {script_id: output}