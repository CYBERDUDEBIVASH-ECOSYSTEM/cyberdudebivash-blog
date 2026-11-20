from automation.content_discovery import DiscoveredArticle
from automation import source_evidence_hydrator as hydration


def _article(url="https://publisher.example/report"):
    return DiscoveredArticle(
        url=url,
        title="Threat report",
        summary="short preview",
        published_at="2026-10-02T10:00:00+00:00",
        content_hash="abc",
        labels=["Threat Intelligence"],
        source="global_rss",
        full_content="short preview",
        source_publisher="Example Research",
    )


def test_private_and_special_destinations_are_rejected_without_http():
    assert hydration._validate_public_destination("http://127.0.0.1/a") is False
    assert hydration._validate_public_destination("http://169.254.169.254/a") is False
    assert hydration._validate_public_destination("http://localhost/a") is False
    assert hydration._validate_public_destination("file:///etc/passwd") is False


def test_public_dns_destination_requires_only_global_addresses(monkeypatch):
    monkeypatch.setattr(
        hydration.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    assert hydration._validate_public_destination("https://publisher.example/report") is True

    monkeypatch.setattr(
        hydration.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.7", 443))],
    )
    assert hydration._validate_public_destination("https://publisher.example/report") is False


def test_selected_rss_hydration_adopts_only_materially_richer_source(monkeypatch):
    article = _article()
    rich = "<html><body><article>" + " ".join(
        f"<p>Evidence paragraph {i} contains source-backed technical context and validation detail.</p>"
        for i in range(180)
    ) + "</article></body></html>"

    monkeypatch.setattr(hydration, "_bounded_get_html", lambda url: rich)
    result = hydration.hydrate_selected_article(article)

    assert result.attempted is True
    assert result.adopted is True
    assert result.after_words > result.before_words + hydration.MIN_RICHER_WORD_GAIN
    assert "Evidence Capture: publisher article page" in article.full_content


def test_non_global_rss_is_never_hydrated(monkeypatch):
    article = _article()
    article.source = "cisa_kev"
    monkeypatch.setattr(
        hydration,
        "_bounded_get_html",
        lambda url: (_ for _ in ()).throw(AssertionError("must not fetch")),
    )

    result = hydration.hydrate_selected_article(article)
    assert result.attempted is False
    assert result.adopted is False


class _Response:
    status_code = 200
    headers = {"Content-Type": "text/html; charset=utf-8"}
    encoding = "utf-8"

    def __init__(self, body: bytes):
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=16384):
        yield self._body

    def close(self):
        self.closed = True


def test_response_body_is_hard_bounded(monkeypatch):
    monkeypatch.setattr(hydration, "_validate_public_destination", lambda url: True)
    response = _Response(b"x" * (hydration.MAX_RESPONSE_BYTES + 50_000))
    monkeypatch.setattr(hydration.requests, "get", lambda *a, **k: response)

    html = hydration._bounded_get_html("https://publisher.example/report")
    assert html is not None
    assert len(html.encode("utf-8")) == hydration.MAX_RESPONSE_BYTES
    assert response.closed is True


def test_selected_first_party_soc_post_carries_its_cited_reporting_url_without_network(
    monkeypatch, tmp_path
):
    from automation.premium_evidence_compiler import deterministic_references
    from automation.report_renderer import _references

    slug = "byod-ransomware-hackers-play-audio-ransom-messages-on-comput"
    article = _article(
        "https://blog.cyberdudebivash.in/posts/" + slug + ".html"
    )
    article.source = "rss"
    article.source_publisher = "CYBERDUDEBIVASH"
    source_url = "https://cybersecuritynews.com/byod-ransomware/"
    markup = (
        '<html><main><div class="cdb-soc12-focus">'
        '<a href="https://tools.cyberdudebivash.com">Advertisement</a>'
        f'<a href="{source_url}" target="_blank" rel="noopener noreferrer">'
        'Open cited source ↗</a>'
        '</div></main></html>'
    )
    (tmp_path / (slug + ".html")).write_text(markup, encoding="utf-8")
    monkeypatch.setattr(hydration, "_SOC_POSTS_DIR", tmp_path)
    monkeypatch.setattr(
        hydration, "_bounded_get_html",
        lambda url: (_ for _ in ()).throw(AssertionError("no network")),
    )
    result = hydration.hydrate_selected_article(article)
    assert result.attempted is False
    assert result.adopted is False
    assert result.reason == "local_soc_citation_captured"
    assert article.cited_external_source_url == source_url
    assert article.full_content == "short preview"
    assert hydration.validated_soc_citation(article) == source_url
    assert ("External reporting cited by SOC (not independently verified)", source_url) in deterministic_references(article)
    rendered = _references(article, None)
    assert source_url in rendered
    assert "not independently verified" in rendered
    assert "https://tools.cyberdudebivash.com" not in rendered
    saved = DiscoveredArticle.from_dict(article.to_dict())
    assert saved.cited_external_source_url == source_url


def test_local_soc_citation_rejects_invalid_source_origin_and_unsafe_outbound_links(
    monkeypatch, tmp_path
):
    slug = "byod-ransomware-hospitals"
    source = "https://blog.cyberdudebivash.in/posts/" + slug + ".html"
    monkeypatch.setattr(hydration, "_SOC_POSTS_DIR", tmp_path)
    monkeypatch.setattr(
        hydration, "_bounded_get_html",
        lambda url: (_ for _ in ()).throw(AssertionError("must not fetch")),
    )
    cases = [
        "javascript:alert(1)",
        "http://cybersecuritynews.com/byod/",
        "https://127.0.0.1/admin",
        "https://169.254.169.254/latest/meta-data/",
        "https://foo.local/private",
        "https://user:password@cybersecuritynews.com/byod/",
        "https://blog.cyberdudebivash.in/posts/a.html",
        "https://soc.cyberdudebivash.in/post/other",
        "https://cybersecuritynews.com:4443/byod/",
    ]
    for unsafe in cases:
        (tmp_path / (slug + ".html")).write_text(
            '<div class="cdb-soc12-focus"><a href="' + unsafe
            + '">Open cited source ↗</a></div>',
            encoding="utf-8",
        )
        article = _article(source)
        article.source = "rss"
        result = hydration.hydrate_selected_article(article)
        assert result.reason == "local_soc_citation_unavailable", unsafe
        assert article.cited_external_source_url is None
        assert hydration.validated_soc_citation(article) is None

    for invalid_source in [
        "https://evil.example/posts/" + slug + ".html",
        "http://blog.cyberdudebivash.in/posts/" + slug + ".html",
        "https://blog.cyberdudebivash.in/posts/../../secret.html",
        "https://blog.cyberdudebivash.in/posts/" + slug + ".html?redirect=1",
        "https://blog.cyberdudebivash.in.evil.example/posts/" + slug + ".html",
    ]:
        article = _article(invalid_source)
        article.source = "rss"
        assert hydration.hydrate_selected_article(article).reason == "local_soc_citation_unavailable"


def test_local_soc_citation_requires_explicit_provenance_anchor_and_bounded_file(
    monkeypatch, tmp_path
):
    slug = "byod-ransomware-hospitals"
    source = "https://blog.cyberdudebivash.in/posts/" + slug + ".html"
    article = _article(source)
    article.source = "rss"
    monkeypatch.setattr(hydration, "_SOC_POSTS_DIR", tmp_path)

    # A random footer URL is not a source citation.
    post = tmp_path / (slug + ".html")
    post.write_text(
        '<footer><a href="https://unrelated.example">Open cited source</a></footer>',
        encoding="utf-8",
    )
    assert hydration.hydrate_selected_article(article).reason == "local_soc_citation_unavailable"

    # Oversized pages are never parsed or promoted to evidence.
    post.write_text("x" * (hydration.MAX_RESPONSE_BYTES + 1), encoding="utf-8")
    assert hydration.hydrate_selected_article(article).reason == "local_soc_citation_unavailable"
