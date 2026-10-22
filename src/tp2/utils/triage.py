import json
import re
from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


class Triage:
    def __init__(self, path: str, backend: str) -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner()
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        matches = self.scanner.scan(sample.data)

        summary = json.dumps({
            "meta": meta,
            "iocs": iocs,
            "yara": matches,
            "bin": bininfo
        })

        try:
            verdict_str = self.llm.triage(summary)
            clean_verdict = re.sub(r"^```json\s*", "", verdict_str.strip())
            clean_verdict = re.sub(r"\s*```$", "", clean_verdict)
            verdict = json.loads(clean_verdict)
        except Exception as e:
            logger.error(f"Erreur parsing JSON du LLM : {e}")
            verdict = {}

        text_data = sample.data.decode("ascii", errors="ignore")
        flag_match = re.search(r'ESGI\{.*?\}', text_data)
        flag_value = flag_match.group(0) if flag_match else "ESGI{not_found}"

        return {
            "sha256": meta.get("sha256", ""),
            "md5": meta.get("md5", ""),
            "size": meta.get("size", 0),
            "entropy": meta.get("entropy", 0.0),
            "file_type": meta.get("file_type", "Unknown"),
            "iocs": iocs,
            "imports": bininfo.get("imports", []),
            "yara_matches": matches,
            "family_guess": verdict.get("family_guess", "unknown"),
            "mitre_attack": verdict.get("mitre_attack", []),
            "llm_summary": verdict.get("llm_summary", "Résumé non disponible."),
            "score": verdict.get("score", 0),
            "flag": flag_value
                }