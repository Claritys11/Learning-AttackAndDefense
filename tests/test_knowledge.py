import pytest
from attnndef.knowledge import (
    AD_ARTICLES,
    GZCTF_ARTICLES,
    get_ad_article,
    get_gzctf_article,
    list_ad_articles,
    list_gzctf_articles,
)

def test_ad_knowledge_articles_completeness():
    articles = list_ad_articles()
    assert len(articles) >= 6

    # Verify key topics required by product direction
    expected_ids = {"overview", "scoring", "loop", "recon_enum", "defense_patching", "traffic_monitoring"}
    actual_ids = {a.id for a in articles}
    assert expected_ids.issubset(actual_ids)

    # Check loop content
    loop_art = get_ad_article("loop")
    assert loop_art is not None
    assert "Observe" in loop_art.content
    assert "Recon" in loop_art.content
    assert "Enumerate" in loop_art.content
    assert "Exploit" in loop_art.content
    assert "Submit Flag" in loop_art.content
    assert "Patch Own Service" in loop_art.content
    assert "Verify Service" in loop_art.content
    assert "Monitor" in loop_art.content

    # Check SLA content
    scoring_art = get_ad_article("scoring")
    assert scoring_art is not None
    assert "SLA" in scoring_art.content
    assert "Attack Points" in scoring_art.content
    assert "Defense Points" in scoring_art.content

def test_gzctf_knowledge_articles_completeness():
    articles = list_gzctf_articles()
    assert len(articles) >= 4

    expected_ids = {"architecture", "flag_mechanics", "sla_checker", "competition_ops"}
    actual_ids = {a.id for a in articles}
    assert expected_ids.issubset(actual_ids)

    # Verify primary source details from refs/GZCTF
    flag_art = get_gzctf_article("flag_mechanics")
    assert flag_art is not None
    assert "GZCTF_FLAG_FILE" in flag_art.content
    assert "flag{" in flag_art.content
    assert "bind mount" in flag_art.content.lower()

    arch_art = get_gzctf_article("architecture")
    assert arch_art is not None
    assert "AdWarmupSeconds" in arch_art.content
    assert "AdTickSeconds" in arch_art.content
    assert "Open Bridge" in arch_art.content or "Open" in arch_art.content

    ops_art = get_gzctf_article("competition_ops")
    assert ops_art is not None
    assert "WireGuard" in ops_art.content
    assert "SSH" in ops_art.content
