import re
class RegexExtractor:
    def __init__(self, pattern: str): self.pattern = re.compile(pattern)
    def extract(self, raw: str) -> list[str]: return list(dict.fromkeys(self.pattern.findall(raw)))
class FlagValidator:
    def __init__(self, pattern: str): self.pattern = re.compile(pattern)
    def validate(self, flags: list[str]) -> list[str]: return list(dict.fromkeys(f for f in flags if self.pattern.fullmatch(f)))
