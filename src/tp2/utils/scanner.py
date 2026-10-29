import yara
import os


class YaraScanner:
    def __init__(self, rules_path: str = "rules/course_rules.yar") -> None:
        self.rules_path = rules_path
        self.rules = None
        self._compile_rules()

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        if not self.rules or not data:
            return []

        try:
            matches = self.rules.match(data=data)
            return [match.rule for match in matches]
        except yara.Error:
            return []

    def _compile_rules(self) -> None:
        if not os.path.exists(self.rules_path):
            return

        try:
            if os.path.isdir(self.rules_path):
                filepaths = {
                    f: os.path.join(self.rules_path, f)
                    for f in os.listdir(self.rules_path)
                    if f.endswith((".yar", ".yara"))
                }
                if filepaths:
                    self.rules = yara.compile(filepaths=filepaths)
            else:
                self.rules = yara.compile(filepath=self.rules_path)
        except yara.Error:
            self.rules = None
