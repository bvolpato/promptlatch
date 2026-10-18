"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { jsonPresentation, renderJSON, fraction, tokenTotal, cost } = require("../src/promptlatch/dashboard_assets/app.js");

test("usage summaries preserve unknown values and mark partial totals", () => {
  assert.equal(fraction(3, 4), 0.75);
  assert.equal(fraction(0, 4), 0);
  for (const [part, total] of [[null, 4], [0, 0], [5, 4], [-1, 4], [1, undefined]]) {
    assert.equal(fraction(part, total), null);
  }
  assert.ok(tokenTotal({ total_tokens: 8, known_token_requests: 1, requests: 3 }).endsWith("+"));
  assert.ok(!tokenTotal({ total_tokens: 0, known_token_requests: 3, requests: 3 }).endsWith("+"));
  assert.equal(tokenTotal({ total_tokens: null, known_token_requests: 0, requests: 3 }), "—");
  assert.ok(tokenTotal({ total_tokens: 8, requests: 3 }).endsWith("+"));
  assert.equal(cost(null), "—");
  assert.notEqual(cost(0), "—");
  assert.notEqual(cost(0.0000001), cost(0));
  assert.notEqual(cost(0.00001), cost(0));
});

function presented(value, truncated = false) {
  const result = jsonPresentation(value, truncated);
  assert.ok(result, "expected JSON presentation");
  return result;
}

function source(result) {
  return result.parts.map((part) => part.text).join("");
}

test("pretty prints nested objects and arrays with two-space indentation", () => {
  const input = '{"request":{"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":[{"type":"text","text":"ok"}]}]}}';
  assert.equal(source(presented(input)), `{
  "request": {
    "messages": [
      {
        "role": "user",
        "content": "hello"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "text",
            "text": "ok"
          }
        ]
      }
    ]
  }
}`);
});

test("formats empty containers and arrays containing containers", () => {
  assert.equal(source(presented('{"object":{},"array":[]}')), `{
  "object": {},
  "array": []
}`);
  assert.equal(source(presented('[{},[],{"nested":[]}]')), `[
  {},
  [],
  {
    "nested": []
  }
]`);
});

test("preserves JSON lexemes, duplicate keys, and escaped content", () => {
  const input = '{"n":900719925474099312345,"n":1.2300E+04,"quote":"\\\"quoted\\\"","path":"C:\\\\tmp"}';
  const result = presented(input);
  assert.equal(source(result), `{
  "n": 900719925474099312345,
  "n": 1.2300E+04,
  "quote": "\\\"quoted\\\"",
  "path": "C:\\\\tmp"
}`);
  assert.equal(result.parts.filter((part) => part.kind === "key").length, 4);
  assert.equal(result.parts.find((part) => part.kind === "number").text, "900719925474099312345");
});

test("leaves prose, code, and invalid non-truncated text unchanged", () => {
  for (const value of [
    "A JSON example: {\"ok\":true}",
    "const payload = {\"ok\":true};",
    "{\"ok\":}",
    "not JSON",
  ]) {
    assert.equal(jsonPresentation(value), null, value);
  }
  assert.equal(jsonPresentation('{"bad":]}', true), null, "truncation must not excuse invalid syntax");
});

test("leaves truncated Python, JavaScript, and prose unchanged", () => {
  for (const value of [
    "{'python': True}",
    "{value: 'javascript'}",
    "{the request ended unexpectedly",
    "[a prose list that never became JSON",
  ]) {
    assert.equal(jsonPresentation(value, true), null, value);
  }
});

test("formats incomplete JSON prefixes without completing their syntax", () => {
  const prefixes = [
    '{"message":"unfinished',
    '{"message":"unfinished\\',
    '{"items":[1,{"ok":true}',
    '{"ok":tru',
    '{"ok":fals',
    '{"ok":nul',
  ];
  for (const prefix of prefixes) {
    const result = presented(prefix, true);
    const output = source(result);
    assert.ok(output.startsWith("{"), prefix);
    assert.equal(output.replace(/\s/g, ""), prefix.replace(/\s/g, ""), prefix);
  }
});

test("preserves valid partial number and Unicode escape tokens", () => {
  const prefixes = ['{"n":-', '{"n":1.', '{"n":1e', '{"n":1e+', '{"s":"\\u12'];
  for (const prefix of prefixes) {
    const output = source(presented(prefix, true));
    assert.equal(output.replace(/\s/g, ""), prefix.replace(/\s/g, ""), prefix);
  }
});

test("rejects invalid escapes, control characters, missing values, and trailing commas", () => {
  const invalid = [
    String.raw`{"s":"bad\q`,
    '{"s":"bad\u0001char',
    '{"value":}',
    '{"value":1,}',
  ];
  for (const prefix of invalid) {
    assert.equal(jsonPresentation(prefix, true), null, prefix);
  }
});

test("assigns distinct syntax kinds to JSON keys and primitive values", () => {
  const result = presented('{"key":"text","n":12,"yes":true,"empty":null}');
  const kinds = new Set(result.parts.map((part) => part.kind));
  for (const kind of ["key", "string", "number", "boolean", "null"]) {
    assert.ok(kinds.has(kind), `missing ${kind} syntax kind`);
  }
});

class FakeNode {
  constructor(tagName = "root") {
    this.tagName = tagName;
    this.className = "";
    this.dataset = {};
    this.children = [];
    this._textContent = "";
    this.classList = { toggle: (name, enabled) => { this[`${name}Enabled`] = enabled; } };
  }

  set textContent(value) { this._textContent = String(value); this.children = []; }
  get textContent() { return this._textContent; }
  replaceChildren(...children) { this.children = children.flatMap((child) => child.children || [child]); }
  addEventListener() {}
}

test("renders JSON as text nodes and spans without HTML parsing", (t) => {
  const createdTags = [];
  global.document = {
    createElement(tagName) { createdTags.push(tagName); return new FakeNode(tagName); },
    createTextNode(value) { return { tagName: "#text", textContent: String(value) }; },
    createDocumentFragment() { return { children: [], append(...nodes) { this.children.push(...nodes); } }; },
  };
  t.after(() => { delete global.document; });

  const node = new FakeNode();
  const payload = '{"note":"</span><script>alert(1)</script>"}';
  renderJSON(node, payload);
  assert.equal(node["json-codeEnabled"], true);
  assert.deepEqual(createdTags, ["span", "span"]);
  assert.ok(node.children.every((child) => child.tagName === "#text" || child.tagName === "span"));
  assert.equal(node.children.map((child) => child.textContent).join(""), `{
  "note": "</span><script>alert(1)</script>"
}`);

  const plain = new FakeNode();
  const markup = '<img src=x onerror="alert(1)">';
  renderJSON(plain, markup);
  assert.equal(plain["json-codeEnabled"], false);
  assert.equal(plain.textContent, markup);
  assert.deepEqual(createdTags, ["span", "span"]);
});

test("bounds formatting expansion, nesting indentation, and highlighted parts", () => {
  const manyTokens = `[${Array.from({ length: 20_000 }, (_, index) => String(index)).join(",")}]`;
  const tokenResult = presented(manyTokens);
  const tokenOutput = source(tokenResult);
  assert.ok(tokenResult.parts.filter((part) => part.kind).length <= 5_000);
  assert.ok(tokenResult.limited);
  assert.ok(tokenOutput.length <= 2 * 1024 * 1024);

  const deepInput = "[".repeat(12_000) + "0" + "]".repeat(12_000);
  const deepResult = presented(deepInput);
  const deepOutput = source(deepResult);
  assert.ok(deepOutput.length <= 2 * 1024 * 1024);
  assert.ok(!deepOutput.includes("  ".repeat(25)));
  assert.equal(deepOutput.replace(/[\r\n ]/g, ""), deepInput);

  const cappedBody = `{"body":"${"x".repeat(256 * 1024 - 12)}"}`;
  const cappedResult = presented(cappedBody);
  assert.ok(source(cappedResult).length <= 256 * 1024 + 512);
});
