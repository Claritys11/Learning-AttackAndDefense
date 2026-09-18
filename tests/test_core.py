import pytest
from attnndef.core import Target, TargetRegistry
from attnndef.attack import RegexExtractor, FlagValidator

def test_registry_rejects_external(tmp_path):
    p = tmp_path / "targets.json"
    p.write_text('[{"id":"x","host":"8.8.8.8","port":1}]')
    with pytest.raises(ValueError): TargetRegistry.from_file(p)

def test_extract_validate_deduplicates():
    flags = RegexExtractor(r"FLAG\{[^}]+\}").extract("FLAG{x} FLAG{x} bad")
    assert FlagValidator(r"FLAG\{[^}]+\}").validate(flags) == ["FLAG{x}"]
