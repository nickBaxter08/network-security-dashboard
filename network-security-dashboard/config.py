import os


class Config:
    """
    App mode controls whether real network scanning is allowed.

    DEMO mode (default): uses realistic sample data only. Safe for a
    public/hosted deployment — never touches a real network.

    LOCAL mode: enables real port scanning against a network you specify.
    Only ever run this against networks/devices you own or have explicit
    permission to test. Intended to be run on your own machine, not on a
    publicly hosted server.
    """

    APP_MODE = os.environ.get("APP_MODE", "demo").lower()  # "demo" or "local"

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = os.environ.get("NVD_API_KEY")  # optional, raises rate limit

    # Common ports checked during a local scan
    SCAN_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080]

    SCAN_TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", 0.5))

    @property
    def is_local_mode(self):
        return self.APP_MODE == "local"


config = Config()
