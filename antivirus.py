import re
from typing import List, Tuple


PATTERN_DEFINITIONS: List[Tuple[str, str]] = [
    (r"rm\s+-rf\s+/", "rm -rf /"),
    (r"rm\s+-rf\s+\*", "rm -rf *"),
    (r"del\s+/f\s+/s", "del /f /s"),
    (r"eval\(", "eval("),
    (r"exec\(", "exec("),
    (r"system\(", "system("),
    (r"popen\(", "popen("),
    (r"base64_decode\(", "base64_decode("),
    (r"base64\.b64decode", "base64.b64decode"),
    (r"subprocess\.call", "subprocess.call"),
    (r"subprocess\.Popen", "subprocess.Popen"),
    (r"os\.system", "os.system"),
    (r"os\.remove", "os.remove"),
    (r"os\.rmdir", "os.rmdir"),
    (r"shutil\.rmtree", "shutil.rmtree"),
    (r"wget.*\|", "wget.*|"),
    (r"curl.*\|", "curl.*|"),
    (r"powershell\s+-Command", "powershell -Command"),
    (r"cmd\s+/c", "cmd /c"),
    (r"(wget|curl).*\|.*(sh|bash)", "下载并执行"),
]

COMPILED_PATTERNS = [
    (re.compile(pattern, flags=re.IGNORECASE), desc)
    for pattern, desc in PATTERN_DEFINITIONS
]


def scan_for_malicious(text: str) -> tuple[bool, str]:
    for regex, desc in COMPILED_PATTERNS:
        if regex.search(text):
            return True, desc
    return False, ""
