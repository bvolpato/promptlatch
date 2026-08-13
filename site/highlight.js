(() => {
  const escapeHtml = (value) =>
    value
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");

  const detectLanguage = (source) => {
    const text = source.trim();
    if (text.startsWith("{") || text.startsWith("[")) return "json";
    if (text.includes("[model_providers.") || /^model\s*=/.test(text)) return "toml";
    if (text.includes("target:") || text.includes("redaction:")) return "yaml";
    if (text.includes("from ") || text.includes("client.") || text.includes("redact_")) {
      return "python";
    }
    if (/^(brew|curl|docker|helm|kubectl|uv|promptlatch|export|mkdir|cp|codex|opencode|claude)\b/m.test(text)) {
      return "bash";
    }
    return "text";
  };

  const patterns = {
    bash: [
      ["string", /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g],
      ["comment", /#[^\n]*/g],
      ["variable", /\$\{?[A-Z0-9_]+\}?/g],
      ["flag", /--?[A-Za-z0-9][A-Za-z0-9-]*/g],
      [
        "keyword",
        /\b(?:brew|promptlatch|export|curl|docker|helm|kubectl|uv|mkdir|cp|codex|opencode|claude|jq|kind)\b/g,
      ],
    ],
    json: [
      ["key", /"(?:\\.|[^"\\])*"(?=\s*:)/g],
      ["string", /"(?:\\.|[^"\\])*"/g],
      ["number", /\b-?\d+(?:\.\d+)?\b/g],
      ["literal", /\b(?:true|false|null)\b/g],
    ],
    python: [
      ["string", /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g],
      ["comment", /#[^\n]*/g],
      ["number", /\b-?\d+(?:\.\d+)?\b/g],
      [
        "keyword",
        /\b(?:from|import|as|client|messages|response|model|max_tokens|input|assert|return|with)\b/g,
      ],
      ["call", /\b[A-Za-z_][A-Za-z0-9_]*(?=\()/g],
    ],
    toml: [
      ["string", /"(?:\\.|[^"\\])*"/g],
      ["section", /\[[^\]\n]+\]/g],
      ["key", /\b[A-Za-z_][A-Za-z0-9_]*(?=\s*=)/g],
      ["number", /\b-?\d+(?:\.\d+)?\b/g],
      ["literal", /\b(?:true|false)\b/g],
    ],
    yaml: [
      ["string", /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g],
      ["comment", /#[^\n]*/g],
      ["key", /^\s*[A-Za-z_][A-Za-z0-9_.-]*(?=\s*:)/gm],
      ["literal", /\b(?:true|false|null)\b/g],
    ],
  };

  const overlaps = (range, ranges) =>
    ranges.some((other) => range.start < other.end && other.start < range.end);

  const collectMatches = (source, language) => {
    const matches = [];
    for (const [type, pattern] of patterns[language]) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(source)) !== null) {
        const value = match[0];
        const range = { start: match.index, end: match.index + value.length, type, value };
        if (!overlaps(range, matches)) matches.push(range);
      }
    }
    return matches.sort((left, right) => left.start - right.start);
  };

  const highlight = (source, language) => {
    const matches = collectMatches(source, language);
    let cursor = 0;
    let output = "";
    for (const match of matches) {
      output += escapeHtml(source.slice(cursor, match.start));
      output += `<span class="tok-${match.type}">${escapeHtml(match.value)}</span>`;
      cursor = match.end;
    }
    return output + escapeHtml(source.slice(cursor));
  };

  for (const block of document.querySelectorAll("pre code")) {
    const source = block.textContent;
    const language = detectLanguage(source);
    block.dataset.language = language;
    if (language === "text") continue;
    block.innerHTML = highlight(source, language);
  }
})();
