import math
import magic
import hashlib
import re
import lief
from collections import Counter


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "entropy": round(self.shannon_entropy(), 2),
            "file_type": magic.from_buffer(self.data),
        }

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        text = self.data.decode("ascii", errors="ignore")
        raw_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        valid_ips = [ip for ip in raw_ips if all(0 <= int(octet) <= 255 for octet in ip.split("."))]

        return {
            "domains": list(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text))),
            "ips": list(set(valid_ips)),
            "urls": list(set(re.findall(r"https?://[a-zA-Z0-9./_?-]+", text))),
            "mutex": list(set(re.findall(r"(?i)(?:Global|Local)\\[a-zA-Z0-9_-]+", text))),
            "registry": list(
                set(re.findall(r"(?i)(?:HKCU|HKLM|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[a-zA-Z0-9_\\]+", text))
            ),
        }

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        result = {"imports": [], "exports": [], "sections": []}
        try:
            binary = lief.parse(self.path)
            if binary:
                if hasattr(binary, "imports"):
                    for imp in binary.imports:
                        for entry in imp.entries:
                            if entry.name:
                                result["imports"].append(entry.name)
                if hasattr(binary, "exported_functions"):
                    for exp in binary.exported_functions:
                        if exp.name:
                            result["exports"].append(exp.name)
                if hasattr(binary, "sections"):
                    for sec in binary.sections:
                        if sec.name:
                            result["sections"].append(sec.name)
        except Exception:
            pass
        result["imports"] = list(set(result["imports"]))
        result["exports"] = list(set(result["exports"]))
        result["sections"] = list(set(result["sections"]))
        return result
