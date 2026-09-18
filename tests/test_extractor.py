from attnndef.attack.extractor import FlagValidator, RegexExtractor


def test_extract_finds_flag():
    ex = RegexExtractor()
    assert ex.extract("noise FLAG{abc123} noise") == "FLAG{abc123}"


def test_extract_none_when_absent():
    assert RegexExtractor().extract("nothing here") is None


def test_validator_rejects_malformed():
    v = FlagValidator()
    assert v.is_well_formed("FLAG{ok}") is True
    assert v.is_well_formed("not a flag") is False
    assert v.is_well_formed(None) is False


def test_validator_dedups():
    v = FlagValidator()
    assert v.accept("FLAG{dup}") is True
    assert v.accept("FLAG{dup}") is False
