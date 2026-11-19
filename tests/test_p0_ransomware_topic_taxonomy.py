"""P0 regression: Cisco Talos malware-C2 research must not become ransomware delivery."""
from datetime import datetime, timezone

from automation.content_discovery import DiscoveredArticle
from automation.publication_scheduler import (
    classify_publication_family,
    ransomware_is_primary_topic,
    ransomware_primary_fields,
)
from automation.premium_factory_throughput import (
    classify_factory_family,
    classify_delivery_class,
)


def report(
    title: str,
    *,
    summary: str = "",
    full_content: str = "",
    labels=None,
    source: str = "global_rss",
):
    return DiscoveredArticle(
        url="https://example.test/research/blockchain-dead-drops",
        title=title,
        summary=summary,
        published_at=datetime.now(timezone.utc).isoformat(),
        content_hash="realitycheck1234",
        labels=labels if labels is not None else ["Malware Research", "Threat Intelligence"],
        source=source,
        full_content=full_content,
        source_publisher="Cisco Talos Intelligence",
    )


def test_real_talos_blockchain_dead_drop_story_not_ransomware():
    article = report(
        "The challenge of defending against bulletproof dead drops on public blockchains",
        summary="Malware command-and-control infrastructure uses immutable ledgers and RPC lookups.",
        full_content=(
            "The paper details malware C2 retrieval from smart contracts, Bitcoin, TRON and Solana. "
            "Historical Cerber ransomware experiments are cited as background, not a new ransomware incident. "
            "Defenders should monitor eth_call and anomalous endpoint beaconing."
        ),
    )
    assert not ransomware_is_primary_topic(article)
    assert classify_publication_family(article) == "malware"
    assert classify_factory_family(article) == "malware"
    assert classify_delivery_class(article) == "malware"


def test_ransomware_source_is_authoritative_explicit_category():
    article = report("Akira victim claim against enterprise", source="ransomware_intel")
    assert ransomware_is_primary_topic(article)
    assert classify_publication_family(article) == "ransomware"
    assert classify_factory_family(article) == "ransomware"
    assert classify_delivery_class(article) == "ransomware"


def test_headline_explicit_ransomware_and_extortion_still_rank_as_ransomware():
    for headline in (
        "Ransomware campaign targets enterprise backups",
        "Cyber-extortion gang claims another victim",
        "Double extortion operation disrupts operations",
    ):
        article = report(headline)
        assert classify_publication_family(article) == "ransomware"
        assert classify_factory_family(article) == "ransomware"
        assert classify_delivery_class(article) == "ransomware"


def test_ransomware_only_in_summary_is_not_enough_to_claim_primary_topic():
    article = report(
        "Blockchain C2 network resilience analysis",
        summary="Researchers mention ransomware and extortion in historical background.",
        full_content="This technical research primarily investigates decentralized command-and-control.",
    )
    assert not ransomware_is_primary_topic(article)
    assert classify_publication_family(article) == "threat_analysis"
    assert classify_factory_family(article) == "threat_analysis"
    assert classify_delivery_class(article) == "threat_analysis"


def test_explicit_editorial_ransomware_label_is_primary_signal():
    article = report(
        "Akira criminal infrastructure bulletin",
        labels=["Threat Intelligence", "Ransomware"],
    )
    assert ransomware_is_primary_topic(article)
    assert classify_publication_family(article) == "ransomware"
    assert classify_factory_family(article) == "ransomware"
    assert classify_delivery_class(article) == "ransomware"


def test_unstructured_reporting_outlet_and_generic_labels_never_imply_ransomware():
    assert not ransomware_primary_fields(
        title="New malware C2 channels on blockchains",
        source="global_rss",
        labels=["Threat Intelligence", "Cisco Talos Research"],
    )
    assert ransomware_primary_fields(
        title="Generic title", source="ransomware_intel", labels=[]
    )
