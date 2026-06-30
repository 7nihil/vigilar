# modules/colors.py
class C:
    RESET  = "\033[0m";  BOLD   = "\033[1m";  RED    = "\033[91m"
    YELLOW = "\033[93m"; GREEN  = "\033[92m";  CYAN   = "\033[96m"
    BLUE   = "\033[94m"; GRAY   = "\033[90m";  WHITE  = "\033[97m"
    PURPLE = "\033[95m"; ORANGE = "\033[33m"

SEVERITY_COLOR = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.BLUE, "LOW": C.GREEN}
STATUS_ICON = {
    "SECURE"         : f"{C.GREEN}🟢 SECURE{C.RESET}",
    "PARTIAL_LEAK"   : f"{C.YELLOW}🟡 PARTIAL LEAK{C.RESET}",
    "CRITICAL_BYPASS": f"{C.RED}🔴 CRITICAL BYPASS{C.RESET}",
    "UNKNOWN"        : f"{C.BLUE}🔵 UNKNOWN{C.RESET}",
}
GUARD_ICON = {
    "SAFE" : f"{C.GREEN}🛡️  SAFE{C.RESET}",
    "UNSAFE": f"{C.RED}⚠️  UNSAFE{C.RESET}",
    "ERROR": f"{C.GRAY}❓ ERROR{C.RESET}",
}