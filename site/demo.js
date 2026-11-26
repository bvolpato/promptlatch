(() => {
  const MASK = "[REDACTED_SECRET]";
  const PLACEHOLDER =
    /^(?:<your[-_](?:api[-_]key|client[-_]secret|password|token|secret)(?:[-_]here)?>|\$\{[a-z_][a-z0-9_]*\})$/i;
  const TOKEN_COUNT = /[0-9]+(?=[^A-Za-z0-9_.-]|$)/y;
  const TOKEN_COUNT_LABEL =
    /(?:budget|cached?|completion|creation|input|max|new|num|output|prompt|read|reasoning|thinking|total)[_-]?tokens\\*["']?\s*[:=]\s*$/i;
  const BLOCK_OPENER =
    /^[ \t}]*(?:async[ \t]+)?(?:case|class|def|elif|except|for|if|match|when|while|with)\b.*:[ \t]*$/;
  const NEXT_STATEMENT = /(?:continue|raise|return)(?=\s|$)|[A-Za-z_][A-Za-z_.-]*(?:[ \t]+[-+*/|&]?=[ \t]|[([])/y;
  const OPENER_WORDS = new Set(
    "and as async await case class def elif except for if in is match not or when while with".split(" "),
  );
  const CODE_REFERENCE = /[A-Za-z_]\w*(?:[ \t]*\.[ \t]*[A-Za-z_]\w*|[ \t]*\([ \t]*\))*[ \t]*[[(]?/y;
  const ASSIGNMENTS = new Set(["assigned_secret", "auth_header"]);
  const SECOND_GROUP = new Set(["signed_url_query_param", "url_credentials"]);

  const rules = globalThis.PROMPTLATCH_RULES.map(([name, source, flags]) => ({
    name,
    pattern: new RegExp(source, `${flags}d`),
  }));

  // Mirrors _is_code_reference in redaction.py: `password = load_password()` is not a secret.
  const isCodeReference = (text, start, end) => {
    let position = start;
    while (position && " \t".includes(text[position - 1])) position -= 1;
    if (!position || text[position - 1] !== "=") return false;
    if (position > 1 && "=!<>:".includes(text[position - 2])) return false;
    if (!text.slice(start, end).includes("(") && !"([".includes(text[end] || " ")) return false;
    CODE_REFERENCE.lastIndex = start;
    const match = CODE_REFERENCE.exec(text);
    return match !== null && match.index + match[0].length >= end;
  };

  const startsAt = (pattern, text, start) => {
    pattern.lastIndex = start;
    return pattern.test(text);
  };

  // Mirrors _is_token_count: `max_tokens: 4096` is not a secret.
  const isTokenCount = (text, start) =>
    startsAt(TOKEN_COUNT, text, start) && TOKEN_COUNT_LABEL.test(text.slice(Math.max(0, start - 32), start));

  // Mirrors _is_next_statement: the indented line after `if token:` is not its value.
  const isNextStatement = (text, start) => {
    let position = start;
    while (position && " \t".includes(text[position - 1])) position -= 1;
    if (position <= 0 || position >= start || text[position - 1] !== "\n") return false;
    if (!startsAt(NEXT_STATEMENT, text, start)) return false;
    const above = text.slice(Math.max(0, position - 513), position - 1);
    const line = above.slice(above.lastIndexOf("\n") + 1);
    if ((line.length === above.length && position > 513) || !BLOCK_OPENER.test(line)) return false;
    // Two plain words in a row are prose, such as `for staging use this password:`.
    const words = line.match(/[A-Za-z_]\w*|[^\w\s]/g) || [];
    const plain = (word) => /^[A-Za-z0-9]/.test(word) && !OPENER_WORDS.has(word);
    return !words.some((word, index) => index > 0 && plain(words[index - 1]) && plain(word));
  };

  // Mirrors _is_next_label: an empty `access_key:` does not take the next line's label.
  const isNextLabel = (text, separator, start, end) => {
    if (!text.slice(separator, start).includes("\n")) return false;
    const secret = text.slice(start, end);
    const name = /^[A-Za-z_][A-Za-z_.-]*/.exec(secret);
    if (name === null) return false;
    const rest = secret.slice(name[0].length);
    return rest === ":" || (rest === "" && /^[ \t]*[:=]/.test(text.slice(end, end + 512)));
  };

  const secretRange = (name, match) => {
    if (ASSIGNMENTS.has(name)) return match.indices.groups.secret;
    if (SECOND_GROUP.has(name)) return match.indices[2];
    return match.indices[0];
  };

  // Each piece is plain text or one redaction. Rules run in order against the current output,
  // as they do in the Python engine.
  const replaceRange = (pieces, start, end, rule) => {
    const result = [];
    let cursor = 0;
    let original = "";
    let pending = null;
    for (const piece of pieces) {
      const from = cursor;
      const to = cursor + piece.out.length;
      cursor = to;
      if (to <= start || from >= end) {
        if (pending && from >= end) {
          result.push(pending);
          pending = null;
        }
        result.push(piece);
        continue;
      }
      if (piece.rule) {
        original += piece.original;
      } else {
        const cutStart = Math.max(start - from, 0);
        const cutEnd = Math.min(end - from, piece.out.length);
        if (cutStart > 0) result.push({ out: piece.out.slice(0, cutStart) });
        original += piece.out.slice(cutStart, cutEnd);
        if (cutEnd < piece.out.length) {
          result.push({ out: MASK, original, rule }, { out: piece.out.slice(cutEnd) });
          pending = null;
          original = "";
          continue;
        }
      }
      pending = { out: MASK, original, rule };
    }
    if (pending) result.push(pending);
    return result;
  };

  const redact = (text) => {
    let pieces = [{ out: text }];
    for (const { name, pattern } of rules) {
      let current = pieces.map((piece) => piece.out).join("");
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(current)) !== null) {
        if (match[0] === "") {
          pattern.lastIndex += 1;
          continue;
        }
        const [start, end] = secretRange(name, match);
        const secret = current.slice(start, end);
        const skip =
          secret === MASK ||
          (ASSIGNMENTS.has(name) &&
            (PLACEHOLDER.test(secret) ||
              isCodeReference(current, start, end) ||
              isTokenCount(current, start) ||
              isNextStatement(current, start) ||
              (!match.groups.value_quote && isNextLabel(current, match.index, start, end))));
        if (skip) {
          pattern.lastIndex = Math.max(start, match.index + 1);
          continue;
        }
        pieces = replaceRange(pieces, start, end, name);
        current = pieces.map((piece) => piece.out).join("");
        pattern.lastIndex = match.index + match[0].length - secret.length + MASK.length;
      }
    }
    return pieces;
  };

  const engine = { redact, text: (value) => redact(value).map((piece) => piece.out).join("") };
  if (typeof module !== "undefined") {
    module.exports = engine;
    return;
  }

  // Sample credentials are fake and split so that secret scanners ignore this file.
  const zeros = (count) => "0".repeat(count);
  const fake = {
    openai: `sk-${"proj"}-FixtureToken${zeros(20)}`,
    github: `gh${"p"}_FixtureToken${zeros(24)}`,
    aws: `AK${"IA"}FIXTURETOKEN0000`,
    npm: `np${"m"}_FixtureToken${zeros(24)}`,
    slack: `xo${"xb"}-FixtureToken-${zeros(12)}`,
    jwt: `ey${"J"}FixtureToken${zeros(8)}.FixturePayload${zeros(6)}.FixtureSignature`,
  };
  const samples = {
    env: [
      "The deploy dies on boot. Here is my .env:",
      "",
      `OPENAI_API_KEY=${fake.openai}`,
      `GITHUB_TOKEN=${fake.github}`,
      "DATABASE_URL=postgres://app:FixturePassw0rd@db:5432/prod",
      `AWS_ACCESS_KEY_ID=${fake.aws}`,
      "AWS_REGION=us-east-1",
      "LOG_LEVEL=debug",
      "",
      "Why does it fail before the health check?",
    ],
    tool: [
      "tool_result  bash  exit=0",
      "$ cat ~/.npmrc .slack.json",
      "",
      `//registry.npmjs.org/:_authToken=${fake.npm}`,
      "save-exact=true",
      "{",
      '  "channel": "#releases",',
      `  "bot_token": "${fake.slack}"`,
      "}",
    ],
    curl: [
      "This request returns 403. What is wrong with it?",
      "",
      "curl https://api.example.com/v2/builds \\",
      `  -H "Authorization: Bearer ${fake.jwt}" \\`,
      '  -H "Content-Type: application/json" \\',
      `  -d '{"ref":"main","webhook_url":"https://hooks.example.com/FixtureToken0000"}'`,
      "",
      `Artifact: https://files.example.com/a.tgz?X-Amz-Expires=300&X-Amz-Sign${"ature"}=FixtureSignature0000`,
    ],
    trace: [
      "Traceback (most recent call last):",
      '  File "app/db.py", line 41, in connect',
      "    password = load_password()",
      "sqlalchemy.exc.OperationalError: could not connect to",
      "  postgresql+psycopg://svc_app:FixturePassw0rd@10.0.4.12/prod",
      "  (Background on this error at: https://sqlalche.me/e/20/e3q8)",
      "",
      "retry: redis://:FixturePassw0rd@cache:6379 client_secret=FixtureSecret0000",
    ],
  };

  const root = document.querySelector("#demo");
  if (!root) return;
  const input = root.querySelector("#demo-input");
  const backdrop = root.querySelector("#demo-backdrop");
  const output = root.querySelector("#demo-output");
  const count = root.querySelector("#demo-count");
  const hits = root.querySelector("#demo-hits");
  const tagCache = new Map();
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  let mode = "full";
  let hmacKey = null;
  let run = 0;

  const tagFor = async (secret) => {
    if (!crypto.subtle) return [...keyBytes.slice(0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("");
    hmacKey ??= crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const digest = await crypto.subtle.sign("HMAC", await hmacKey, new TextEncoder().encode(secret));
    return [...new Uint8Array(digest, 0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = text;
    return element;
  };

  const render = async ({ sweep = false } = {}) => {
    const current = (run += 1);
    const pieces = redact(input.value);
    const redactions = pieces.filter((piece) => piece.rule);
    if (mode === "tagged") {
      for (const { original } of redactions) {
        if (!tagCache.has(original)) tagCache.set(original, await tagFor(original));
      }
      if (current !== run) return;
    }
    backdrop.replaceChildren(
      ...pieces.map((piece) => (piece.rule ? node("mark", "", piece.original) : node("span", "", piece.out))),
      "\n",
    );
    output.classList.toggle("sweep", sweep);
    let index = 0;
    output.replaceChildren(
      ...pieces.map((piece) => {
        if (!piece.rule) return node("span", "", piece.out);
        const label = mode === "tagged" ? `[REDACTED:${piece.rule}#${tagCache.get(piece.original)}]` : MASK;
        const bar = node("span", "bar", label);
        bar.style.setProperty("--i", String((index += 1)));
        return bar;
      }),
    );
    count.textContent = `${redactions.length} ${redactions.length === 1 ? "redaction" : "redactions"}`;
    const totals = new Map();
    for (const { rule } of redactions) totals.set(rule, (totals.get(rule) || 0) + 1);
    hits.replaceChildren(
      ...[...totals].map(([rule, total]) => node("li", "", total > 1 ? `${rule} ×${total}` : rule)),
    );
    syncScroll();
  };

  const syncScroll = () => {
    backdrop.scrollTop = input.scrollTop;
    backdrop.scrollLeft = input.scrollLeft;
  };

  const press = (group, active) => {
    for (const button of group) button.setAttribute("aria-pressed", String(button === active));
  };

  const sampleButtons = [...root.querySelectorAll("[data-sample]")];
  for (const button of sampleButtons) {
    button.addEventListener("click", () => {
      press(sampleButtons, button);
      input.value = samples[button.dataset.sample].join("\n");
      input.scrollTop = 0;
      render({ sweep: true });
    });
  }
  const modeButtons = [...root.querySelectorAll("[data-mode]")];
  for (const button of modeButtons) {
    button.addEventListener("click", () => {
      press(modeButtons, button);
      mode = button.dataset.mode;
      render({ sweep: true });
    });
  }
  input.addEventListener("input", () => {
    press(sampleButtons, null);
    render();
  });
  input.addEventListener("scroll", syncScroll, { passive: true });

  input.value = samples.env.join("\n");
  render({ sweep: true });
  root.classList.add("live");
})();
