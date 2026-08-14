import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_release_docs_reference_current_artifacts() -> None:
    version = _version()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    prompt = (ROOT / "PROMPT.md").read_text(encoding="utf-8")
    combined = readme + site

    assert "uv tool install promptlatch" in combined
    assert "uv add promptlatch" in combined
    assert f"releases/download/v{version}/promptlatch-{version}.tgz" in combined
    assert f"ghcr.io/bvolpato/promptlatch:{version}" in combined
    assert "uv tool install promptlatch" in prompt
    assert "uv add promptlatch" in prompt
    assert f"ghcr.io/bvolpato/promptlatch:{version}" in prompt
    assert "0.1.3" not in combined


def test_docs_use_pypi_install() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")

    assert "uv tool install promptlatch" in readme
    assert "uv add promptlatch" in readme
    assert "uv tool install promptlatch" in site
    assert "uv add promptlatch" in site


def test_site_uses_local_syntax_highlighting() -> None:
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")

    assert '<script src="./highlight.js" defer></script>' in site
    assert (ROOT / "site" / "highlight.js").is_file()


def test_site_publishes_agent_integration_prompt() -> None:
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    prompt = (ROOT / "PROMPT.md").read_text(encoding="utf-8")
    published_prompt = (ROOT / "site" / "PROMPT.md").read_text(encoding="utf-8")

    assert '<script src="./prompt.js" defer></script>' in site
    assert 'data-prompt-url="./PROMPT.md"' in site
    assert (ROOT / "site" / "prompt.js").is_file()
    assert published_prompt == prompt


def test_site_local_assets_exist() -> None:
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")

    for source in re.findall(r'src="\./([^"?]+)', site):
        assert (ROOT / "site" / source).is_file(), source


def test_site_dynamic_target_example_includes_allowlist() -> None:
    site = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    openrouter_example = site.split("<h3>OpenRouter request</h3>", 1)[1].split("</article>", 1)[0]

    assert "allowed_base_urls" in openrouter_example
    assert "https://openrouter.ai/api/v1" in openrouter_example
