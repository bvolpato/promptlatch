"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    authenticated: false, epoch: 0, days: 30, threadOffset: 0, traffic: "inference",
    sessionExpiresAt: null, locking: false, lockError: false,
    threads: { items: [], total: 0 }, summary: null,
    threadId: null, threadInfo: null, expanded: true,
    session: { items: [], total: 0, offset: 0, limit: 100 },
    sessionLoading: false, treeVersion: 0, collapsedTurns: new Set(),
    requestId: null, detail: null, detailVersion: 0, tab: "conversation",
    view: "empty", inspectorView: "empty", initialized: false,
    refreshing: false, refreshAgain: false, treeSignature: "", sessionSignature: "",
    routeVersion: 0, locationHash: null,
  };
  const number = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
  const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
  const decimal = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
  const money = new Intl.NumberFormat(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 4 });
  const known = (value) => typeof value === "number" && Number.isFinite(value);
  const count = (value) => known(value) ? number.format(value) : "—";
  const tokens = (value) => known(value) ? compact.format(value) : "—";
  const cost = (value) => known(value) ? money.format(value) : "—";
  const apiEquivalent = (item) => ["litellm_api_equivalent", "custom_api_equivalent"].includes(item.cost_source);
  const duration = (value) => known(value) ? value >= 1000 ? `${decimal.format(value / 1000)}s` : `${number.format(value)}ms` : "—";
  const speed = (value) => known(value) ? decimal.format(value) : "—";
  const text = (id, value) => { $(id).textContent = value; };
  const shortId = (id) => id ? id.length > 17 ? `${id.slice(0, 9)}…${id.slice(-5)}` : id : "Unknown";
  const date = (timestamp, full = false) => known(timestamp) ? new Date(timestamp * 1000).toLocaleString(undefined, full ? {} : { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
  const time = (timestamp) => known(timestamp) ? new Date(timestamp * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
  const element = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = String(value);
    return node;
  };
  const button = (className, label, handler, focusKey) => {
    const node = element("button", className, label);
    node.type = "button";
    if (focusKey) node.dataset.focusKey = focusKey;
    node.addEventListener("click", handler);
    return node;
  };
  const pretty = (value) => {
    if (typeof value === "string") {
      try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; }
    }
    return JSON.stringify(value, null, 2) ?? "";
  };
  const preview = (value, limit = 220) => {
    if (typeof value !== "string") return "";
    const normalized = value.replace(/\s+/g, " ").trim();
    if (!normalized) return "";
    const chars = Array.from(normalized);
    return chars.length > limit ? `${chars.slice(0, limit).join("")}…` : normalized;
  };
  const metadata = (id) => state.session.items.find((item) => item.request_id === id);
  const ordinal = (item, index = 0) => item.ordinal || state.session.total - state.session.offset - index;
  const turnKey = (item) => item.turn_id ? `id:${item.turn_id}` : known(item.user_turn) ? `turn:${item.user_turn}` : null;
  const failed = (item) => item.outcome && !["active", "success", "unknown"].includes(item.outcome);
  const statusClass = (item) => !item.outcome || item.outcome === "unknown" ? " unknown" : item.outcome === "active" ? " pending" : failed(item) ? " error" : "";
  const statusLabel = (item) => item.outcome === "active" ? "Active" : item.outcome === "success" ? "Completed" : `${item.status_code ? `${item.status_code} · ` : ""}${(item.outcome || "unknown").replaceAll("_", " ")}`;
  const badge = (item) => element("span", `status-badge${statusClass(item)}`, statusLabel(item));
  const statusDot = (item) => {
    const node = element("span", `status-dot${statusClass(item)}`, item.outcome === "success" ? "✓" : failed(item) ? "!" : "•");
    node.title = statusLabel(item);
    node.setAttribute("aria-label", statusLabel(item));
    return node;
  };
  const threadStatus = (item) => ({ outcome: item.active_requests ? "active" : item.latest_outcome });
  const threadCost = (item) => `${cost(item.cost_usd)}${known(item.cost_usd) && item.known_cost_requests < item.requests ? "+" : ""}`;
  const validRequestId = (id) => typeof id === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(id);

  function locationRoute() {
    const hash = location.hash.slice(1);
    if (!hash || hash === "requests") return { view: "requests" };
    if (hash === "stats") return { view: "overview" };
    const params = new URLSearchParams(hash);
    const id = params.get("request");
    if (params.size === 1 && params.getAll("request").length === 1 && validRequestId(id)) return { view: "request", id };
    return { view: "invalid" };
  }

  function writeLocation(hash, mode = "push") {
    if (mode === "none") return;
    const target = `#${hash}`;
    state.locationHash = target;
    if (location.hash === target) return;
    history[mode === "replace" ? "replaceState" : "pushState"](null, "", `${location.pathname}${location.search}${target}`);
  }

  function requestHash(id) {
    return `request=${encodeURIComponent(id)}`;
  }

  function requestLink(id) {
    const link = new URL(location.pathname, location.origin);
    link.hash = requestHash(id);
    return link.href;
  }

  async function navigateLocation({ initial = false } = {}) {
    if (!state.authenticated) return;
    const hash = location.hash;
    if (!initial && hash === state.locationHash) return;
    state.locationHash = hash;
    const version = ++state.routeVersion;
    const route = locationRoute();
    state.initialized = true;
    if (route.view === "request") {
      await selectRequest(route.id, { historyMode: "none" });
    } else if (route.view === "overview") {
      state.detailVersion += 1;
      state.sessionLoading = false;
      showView("overview"); toggleSidebar(false); renderTree();
    } else if (route.view === "invalid") {
      state.detailVersion += 1;
      state.requestId = state.detail = null;
      showEmpty("Invalid request link", "The link must contain one valid request ID. Select a request from the sidebar or open Stats.");
      renderTree();
    } else if (initial && state.threads.items.length) {
      await selectSession(state.threads.items[0], { latest: true, keepSidebar: true, historyMode: "replace" });
    } else {
      state.detailVersion += 1;
      state.requestId = state.detail = null;
      if (state.threadId) { showView("session"); renderSession(); }
      else showEmpty("Select a request", "Choose a session from the sidebar to inspect its retained requests.");
      renderTree();
    }
    if (version !== state.routeVersion) return;
    updateIterationNavigation();
  }

  function replaceKeepingPosition(container, children) {
    const scroll = container.scrollTop;
    const active = document.activeElement;
    const key = container.contains(active) ? active.dataset?.focusKey : null;
    container.replaceChildren(...children);
    if (key) Array.from(container.querySelectorAll("[data-focus-key]")).find((node) => node.dataset.focusKey === key)?.focus({ preventScroll: true });
    container.scrollTop = scroll;
  }

  function clearLegacyTokens() {
    try {
      for (let index = sessionStorage.length - 1; index >= 0; index -= 1) {
        const key = sessionStorage.key(index);
        if (key === "promptlatch.dashboard.token" || key?.startsWith("promptlatch.dashboard.token:")) sessionStorage.removeItem(key);
      }
    } catch { /* Session storage may be disabled. */ }
  }

  function toggleSidebar(open) {
    $("workbench").classList.toggle("sidebar-open", open);
    $("session-toggle").setAttribute("aria-expanded", String(open));
    $("session-toggle").setAttribute("aria-label", open ? "Hide sessions" : "Show sessions");
  }

  function showView(view) {
    state.view = view;
    if (view !== "overview") state.inspectorView = view;
    $("workbench").classList.toggle("overview-active", view === "overview");
    $("session-toggle").hidden = view === "overview";
    for (const name of ["empty", "session", "request", "overview"]) $(name + "-view").hidden = name !== view;
    for (const name of ["inspector", "overview"]) {
      const selected = (view === "overview") === (name === "overview");
      $("nav-" + name).classList.toggle("selected", selected);
      if (selected) $("nav-" + name).setAttribute("aria-current", "page");
      else $("nav-" + name).removeAttribute("aria-current");
    }
  }

  function showEmpty(title, description) {
    text("empty-title", title);
    text("empty-description", description);
    showView("empty");
  }

  function setSessionExpiry(expiresAt) {
    state.sessionExpiresAt = known(expiresAt) ? expiresAt : null;
    const label = state.sessionExpiresAt === null ? "" : `Browser session expires ${date(state.sessionExpiresAt, true)}`;
    text("auth-session-expiry", label);
    $("auth-session-expiry").hidden = !label;
    $("signout").title = label;
  }

  function clearLocalSession(message = "") {
    state.authenticated = false;
    state.locking = false;
    state.lockError = false;
    state.epoch += 1;
    state.treeVersion += 1;
    state.detailVersion += 1;
    state.routeVersion += 1;
    state.locationHash = null;
    state.threadId = state.requestId = state.detail = state.threadInfo = null;
    state.threads = { items: [], total: 0 };
    state.session = { items: [], total: 0, offset: 0, limit: 100 };
    state.threadOffset = 0;
    state.initialized = false;
    state.treeSignature = state.sessionSignature = "";
    state.collapsedTurns.clear();
    state.refreshAgain = false;
    setSessionExpiry(null);
    clearLegacyTokens();
    $("dashboard").hidden = true;
    $("signin").hidden = false;
    $("dashboard-token").value = "";
    $("signin-submit").disabled = false;
    $("retry-session").hidden = true;
    $("retry-session").disabled = false;
    $("signout").disabled = false;
    $("signout").textContent = "Lock";
    $("load-error").hidden = true;
    for (const id of ["session-tree", "session-requests", "conversation-content", "request-metrics"]) $(id).replaceChildren();
    text("request-payload", "");
    $("request-link").hidden = true;
    $("request-link").value = "";
    $("copy-request-link").disabled = true;
    text("copy-link-status", "");
    text("signin-error", message);
    $("signin-error").hidden = !message;
    toggleSidebar(false);
    $("dashboard-token").focus();
  }

  async function api(path, { method = "GET", bearerToken } = {}) {
    const headers = bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {};
    const response = await fetch(new URL(path.replace(/^\//, ""), document.baseURI), {
      method, headers, cache: "no-store",
      credentials: "same-origin", redirect: "error", signal: AbortSignal.timeout(12000),
    });
    if (!response.ok) {
      const error = new Error(response.status === 401 ? bearerToken ? "Dashboard token was rejected. Check the token file and try again." : "Dashboard session expired. Enter your dashboard token." : response.status === 403 ? "Open the dashboard directly using its server address." : "History is temporarily unavailable.");
      error.status = response.status;
      throw error;
    }
    if (response.status === 204) return null;
    return response.json();
  }

  async function endSession() {
    if (!state.authenticated || state.locking) return;
    const epoch = ++state.epoch;
    state.locking = true;
    state.lockError = false;
    $("signout").disabled = true;
    $("signout").textContent = "Locking…";
    $("load-error").hidden = true;
    try {
      await api("/api/session", { method: "DELETE" });
      if (epoch !== state.epoch) return;
      clearLocalSession();
    } catch (error) {
      if (epoch !== state.epoch) return;
      if (error.status === 401) { clearLocalSession(); return; }
      state.locking = false;
      state.lockError = true;
      $("signout").disabled = false;
      $("signout").textContent = "Retry lock";
      text("load-error", "Could not end the browser session. You are still signed in; select Retry lock.");
      $("load-error").hidden = false;
    }
  }

  async function activateSession(session, epoch) {
    if (epoch !== state.epoch) return;
    state.authenticated = true;
    state.locking = false;
    state.lockError = false;
    setSessionExpiry(session?.expires_at);
    $("signin-error").hidden = true;
    $("retry-session").hidden = true;
    $("retry-session").disabled = false;
    $("signin").hidden = true;
    $("dashboard").hidden = false;
    state.initialized = true;
    showEmpty("Loading activity", "Reading local request history…");
    await refresh();
    if (epoch === state.epoch) await navigateLocation({ initial: true });
  }

  async function restoreSession() {
    const epoch = ++state.epoch;
    $("retry-session").disabled = true;
    $("retry-session").hidden = true;
    $("signin-error").hidden = true;
    try {
      const session = await api("/api/session");
      if (epoch !== state.epoch) return;
      await activateSession(session, epoch);
    } catch (error) {
      if (epoch !== state.epoch) return;
      if (error.status === 401) {
        state.authenticated = false;
        setSessionExpiry(null);
        return;
      }
      text("signin-error", "Could not check for an existing browser session. Retry or enter your dashboard token.");
      $("signin-error").hidden = false;
      $("retry-session").hidden = false;
    } finally {
      if (epoch === state.epoch) $("retry-session").disabled = false;
    }
  }

  function sessionPath(id, offset) {
    return `/api/threads/${encodeURIComponent(id)}/requests?limit=100&offset=${offset}&order=desc&traffic=${state.traffic}`;
  }

  function threadsPath(offset) {
    return `/api/threads?limit=50&offset=${offset}&traffic=${state.traffic}`;
  }

  function iterationNode(item, index) {
    const li = element("li");
    const node = button(`iteration-button${state.requestId === item.request_id ? " selected" : ""}`, undefined, () => selectRequest(item.request_id), `request:${item.request_id}`);
    const userPreview = preview(item.user_preview);
    const assistantPreview = preview(item.assistant_preview);
    node.title = [`Iteration ${ordinal(item, index)} · ${item.model || "Unknown model"} · ${statusLabel(item)}`, userPreview, assistantPreview ? `Previous answer from captured request history: ${assistantPreview}` : ""].filter(Boolean).join("\n");
    if (state.requestId === item.request_id) node.setAttribute("aria-current", "page");
    node.append(statusDot(item));
    const name = element("span", "iteration-name");
    const top = element("span", "row-topline");
    top.append(element("span", "iteration-model", item.model || "Unknown model"), element("span", "row-duration", duration(item.duration_ms)), element("span", "row-cost", cost(item.cost_usd)));
    name.append(top);
    const bottom = element("span", "row-bottomline");
    const prompt = element("span", "iteration-preview user-preview");
    prompt.append(element("span", "iteration-ordinal", `${ordinal(item, index)}/${count(state.session.total)} `), document.createTextNode(userPreview || `Request ${shortId(item.request_id)}`));
    bottom.append(prompt, element("span", "iteration-time", time(item.started_at)));
    name.append(bottom);
    if (assistantPreview) {
      const previous = element("span", "iteration-preview assistant-preview");
      previous.append(element("span", "preview-label", "Previous answer: "), document.createTextNode(assistantPreview));
      name.append(previous);
    }
    node.append(name);
    li.append(node);
    return li;
  }

  function sessionChildren() {
    const children = element("div", "session-children");
    if (state.sessionLoading) {
      children.append(element("p", "tree-page-note", "Loading iterations…"));
      return children;
    }
    const { items, total, offset } = state.session;
    if (!items.length) {
      children.append(element("p", "tree-page-note", "No retained iterations"));
      return children;
    }
    if (total > 100) children.append(element("p", "tree-page-note", `Showing ${offset + 1}–${offset + items.length} of ${count(total)} iterations`));
    const list = element("ul", "iteration-list");
    let group = null;
    let previousKey = null;
    items.forEach((item, index) => {
      const key = turnKey(item);
      if (!key) {
        group = null;
        previousKey = null;
        list.append(iterationNode(item, index));
        return;
      }
      if (key !== previousKey) {
        const li = element("li", "turn-node");
        const collapsed = state.collapsedTurns.has(key);
        const label = known(item.user_turn) ? `Turn ${item.user_turn}` : "User turn";
        const toggle = button("turn-button", undefined, () => {
          if (state.collapsedTurns.has(key)) state.collapsedTurns.delete(key);
          else state.collapsedTurns.add(key);
          renderTree();
        }, `turn:${key}`);
        toggle.setAttribute("aria-expanded", String(!collapsed));
        const heading = element("span", "turn-heading");
        heading.append(element("span", "", collapsed ? "›" : "⌄"), element("span", "", label));
        if (item.turn_source === "inferred") heading.append(element("span", "inferred", "inferred"));
        toggle.append(heading);
        const userPreview = preview(item.user_preview);
        if (userPreview) {
          const prompt = element("span", "turn-preview");
          prompt.append(element("span", "preview-label", "User: "), document.createTextNode(userPreview));
          toggle.append(prompt);
        }
        group = element("ul", "turn-list");
        group.hidden = collapsed;
        li.append(toggle, group);
        list.append(li);
        previousKey = key;
      }
      group.append(iterationNode(item, index));
    });
    children.append(list);
    if (total > 100) {
      const pager = element("div", "tree-pager");
      const earlier = button("", "← Newer", () => changeSessionPage(Math.max(0, offset - 100)), "tree-earlier");
      const later = button("", "Older →", () => changeSessionPage(offset + 100), "tree-later");
      earlier.disabled = offset === 0;
      later.disabled = offset + items.length >= total;
      pager.append(earlier, later);
      children.append(pager);
    }
    return children;
  }

  function renderTree() {
    $("filter-traffic").value = state.traffic;
    const query = $("thread-search").value.toLowerCase().trim();
    const filters = [$("filter-status").value, $("filter-provider").value, $("filter-model").value];
    const signature = JSON.stringify([state.traffic, state.threads, state.threadId, state.requestId, state.expanded, state.view, state.session, state.sessionLoading, [...state.collapsedTurns], query, filters]);
    if (signature === state.treeSignature) return;
    state.treeSignature = signature;
    const matches = state.threads.items.filter((item) => {
      const searchable = `${item.thread_id} ${item.thread_source} ${item.latest_model || ""} ${item.latest_provider || ""} ${preview(item.session_preview, 4096)} ${preview(item.last_user_preview, 4096)} ${preview(item.last_assistant_preview, 4096)}`.toLowerCase();
      const outcome = threadStatus(item).outcome;
      return searchable.includes(query) && (!filters[0] || (filters[0] === "error" ? outcome && !["success", "active"].includes(outcome) : outcome === filters[0])) && (!filters[1] || item.latest_provider === filters[1]) && (!filters[2] || item.latest_model === filters[2]);
    });
    const selectedThread = state.threads.items.find((item) => item.thread_id === state.threadId) || state.threadInfo;
    const pinned = selectedThread && !matches.some((item) => item.thread_id === selectedThread.thread_id) ? selectedThread : null;
    const visible = pinned ? [pinned, ...matches] : matches;
    const list = element("ul", "session-list");
    for (const item of visible) {
      const selected = state.threadId === item.thread_id;
      const li = element("li", "session-node");
      const row = element("div", `session-row${selected ? " selected" : ""}`);
      const expand = button("session-expand", selected && state.expanded ? "⌄" : "›", () => {
        if (selected) { state.expanded = !state.expanded; renderTree(); }
        else selectSession(item, { keepSidebar: true });
      }, `expand:${item.thread_id}`);
      expand.setAttribute("aria-label", `${selected && state.expanded ? "Collapse" : "Expand"} session ${shortId(item.thread_id)}`);
      expand.setAttribute("aria-expanded", String(selected && state.expanded));
      const select = button("session-button", undefined, () => selectSession(item), `session:${item.thread_id}`);
      const sessionPreview = preview(item.last_user_preview) || preview(item.session_preview);
      select.title = sessionPreview ? `Session ${item.thread_id}\n${sessionPreview}` : `Session ${item.thread_id}`;
      const top = element("span", "row-topline");
      const price = element("span", "row-cost", threadCost(item));
      if (known(item.cost_usd)) price.title = `Estimated cost for ${count(item.known_cost_requests)} of ${count(item.requests)} requests${item.known_cost_requests < item.requests ? "; unpriced requests excluded" : ""}`;
      const name = item.latest_model || (item.latest_method ? `${item.latest_method} ${item.latest_path || ""}`.trim() : `Session ${shortId(item.thread_id)}`);
      top.append(element("span", "session-name", name), element("span", "count-badge", `${count(item.requests)} requests`), element("span", "row-duration", duration(item.duration_ms)), price);
      select.append(top);
      const meta = element("span", "session-meta");
      meta.append(element("span", "session-prompt", sessionPreview || `${item.latest_provider || "Unknown provider"} · ${shortId(item.thread_id)}`), element("span", "session-time", time(item.latest_started_at ?? item.last_started_at)));
      select.append(meta);
      if (selected && state.view === "session") select.setAttribute("aria-current", "page");
      row.append(statusDot(threadStatus(item)), expand, select);
      if (item === pinned) li.append(element("p", "pinned-selection", state.threads.items.includes(item) ? "Selected session outside filters" : "Selected session outside loaded page"));
      li.append(row);
      if (selected && state.expanded) li.append(sessionChildren());
      list.append(li);
    }
    replaceKeepingPosition($("session-tree"), visible.length ? [list] : [element("p", "empty-small", query || filters.some(Boolean) ? "No matching loaded sessions" : "No sessions recorded")]);
    const requests = matches.reduce((total, item) => total + (item.requests || 0), 0);
    text("session-total", `${count(matches.length)} sessions · ${count(requests)} requests`);
    text("filter-scope", `${state.traffic === "inference" ? "Inference requests only." : "All HTTP traffic, including ancillary calls."} Other filters apply to ${count(state.threads.items.length)} loaded sessions.`);
    text("threads-page", state.threads.total ? `${state.threadOffset + 1}–${Math.min(state.threadOffset + 50, state.threads.total)} of ${count(state.threads.total)}` : "0 sessions");
    $("threads-prev").disabled = state.threadOffset === 0;
    $("threads-next").disabled = state.threadOffset + 50 >= state.threads.total;
  }

  function updateFilterOptions() {
    for (const [name, field, label] of [["provider", "latest_provider", "Any provider"], ["model", "latest_model", "Any model"]]) {
      const select = $("filter-" + name);
      const selected = select.value;
      const values = [...new Set(state.threads.items.map((item) => item[field]).filter((value) => typeof value === "string" && value))].sort();
      if (selected && !values.includes(selected)) values.push(selected);
      const signature = JSON.stringify(values);
      if (select.dataset.options === signature) continue;
      select.dataset.options = signature;
      const any = element("option", "", label); any.value = "";
      select.replaceChildren(any, ...values.map((value) => {
        const option = element("option", "", value); option.value = value; return option;
      }));
      select.value = selected;
    }
  }

  async function selectSession(item, { latest = false, keepSidebar = false, historyMode = "push" } = {}) {
    if (!keepSidebar) toggleSidebar(false);
    if (state.threadId === item.thread_id && !latest) {
      state.expanded = true;
      await loadSessionPage(0, "first", historyMode);
      return;
    }
    state.threadId = item.thread_id;
    state.threadInfo = item;
    state.expanded = true;
    state.requestId = state.detail = null;
    state.detailVersion += 1;
    state.collapsedTurns.clear();
    state.session = { items: [], total: item.requests || 0, offset: 0, limit: 100 };
    state.sessionSignature = "";
    if (latest && state.view === "overview") state.inspectorView = "session";
    else showView("session");
    await loadSessionPage(0, "first", historyMode);
  }

  async function loadSessionPage(offset, selectEdge = null, historyMode = "push") {
    const id = state.threadId;
    const epoch = state.epoch;
    const version = ++state.treeVersion;
    const requestVersion = state.detailVersion;
    state.sessionLoading = true;
    renderTree();
    renderSession();
    updateIterationNavigation();
    try {
      let page = await api(sessionPath(id, offset));
      if (epoch !== state.epoch || version !== state.treeVersion || id !== state.threadId) return;
      if (page.total && offset >= page.total) {
        offset = Math.floor((page.total - 1) / 100) * 100;
        page = await api(sessionPath(id, offset));
      }
      if (epoch !== state.epoch || version !== state.treeVersion || id !== state.threadId) return;
      state.session = page;
      state.sessionLoading = false;
      renderTree();
      renderSession();
      updateIterationNavigation();
      if (selectEdge && page.items.length && requestVersion === state.detailVersion) await selectRequest(page.items[selectEdge === "last" ? page.items.length - 1 : 0].request_id, { keepSidebar: true, background: state.view === "overview", historyMode });
    } catch (error) {
      if (epoch !== state.epoch || version !== state.treeVersion) return;
      state.sessionLoading = false;
      if (error.status === 401) { clearLocalSession(); return; }
      text("load-error", "Could not load session iterations. Use Refresh to retry.");
      $("load-error").hidden = false;
      renderTree();
      renderSession();
    }
  }

  function changeSessionPage(offset) {
    if (state.sessionLoading) return;
    loadSessionPage(offset);
  }

  function renderSession() {
    if (!state.threadId) return;
    const info = state.threads.items.find((item) => item.thread_id === state.threadId) || state.threadInfo || {};
    const signature = JSON.stringify([info, state.session, state.sessionLoading]);
    if (signature === state.sessionSignature) return;
    state.sessionSignature = signature;
    text("session-title", preview(info.session_preview, 100) || `Session ${shortId(state.threadId)}`);
    text("session-subtitle", state.threadId);
    text("session-source", `${info.thread_source || "unknown"} grouping`);
    const summary = $("session-summary");
    summary.replaceChildren();
    for (const [value, label] of [[count(info.requests ?? state.session.total), "requests"], [duration(info.duration_ms), "duration"], [threadCost(info), "estimated cost"], [tokens(info.total_tokens), "tokens"], [count(info.redactions || 0), "redaction matches"], [count(info.active_requests || 0), "active"]]) {
      const item = element("span"); item.append(element("strong", "", value), document.createTextNode(label));
      if (label === "estimated cost" && known(info.cost_usd) && info.known_cost_requests < info.requests) item.title = `Estimated cost for ${count(info.known_cost_requests)} of ${count(info.requests)} requests; unpriced requests excluded.`;
      summary.append(item);
    }
    summary.append(element("span", "", `Started ${date(info.started_at)}`));
    const { items, offset, total } = state.session;
    const rows = items.map((item, index) => {
      const row = element("tr");
      const first = element("td");
      first.className = "iteration-cell";
      first.append(button("table-button", `Iteration ${ordinal(item, index)}`, () => selectRequest(item.request_id), `row:${item.request_id}`), element("span", "cell-subtitle", date(item.started_at)));
      if (known(item.user_turn)) first.append(element("span", "cell-subtitle", `Turn ${item.user_turn}${item.turn_source === "inferred" ? " · inferred" : ""}`));
      const userPreview = preview(item.user_preview);
      if (userPreview) {
        const prompt = element("span", "cell-preview user-preview");
        prompt.append(element("span", "preview-label", "User: "), document.createTextNode(userPreview));
        first.append(prompt);
      }
      const assistantPreview = preview(item.assistant_preview);
      if (assistantPreview) {
        const previous = element("span", "cell-preview assistant-preview");
        previous.append(element("span", "preview-label", "Previous answer: "), document.createTextNode(assistantPreview));
        first.append(previous);
      }
      const model = element("td"); model.append(element("span", "model-cell", item.model || "Unknown model"));
      const status = element("td"); status.append(badge(item));
      row.append(first, model, status, element("td", "", tokens(item.total_tokens)), element("td", "", duration(item.ttft_ms)), element("td", "", speed(item.tps)), element("td", "", count(item.redactions || 0)), element("td", "", cost(item.cost_usd)));
      return row;
    });
    const scroll = $("session-history").scrollTop;
    replaceKeepingPosition($("session-requests"), rows);
    $("session-history").scrollTop = scroll;
    text("session-range", state.sessionLoading ? "Loading…" : `${count(total)} retained`);
    text("session-page", total ? `${offset + 1}–${offset + items.length} of ${count(total)}` : "0 iterations");
    $("session-empty").hidden = !!items.length || state.sessionLoading;
    $("session-prev").disabled = state.sessionLoading || offset === 0;
    $("session-next").disabled = state.sessionLoading || offset + items.length >= total;
  }

  function updateIterationNavigation() {
    const index = state.session.items.findIndex((item) => item.request_id === state.requestId);
    $("request-prev").disabled = index < 0 || (index === 0 && state.session.offset === 0) || state.sessionLoading;
    $("request-next").disabled = index < 0 || state.session.offset + index + 1 >= state.session.total || state.sessionLoading;
    const item = metadata(state.requestId);
    if (item) text("request-ordinal", `Iteration ${ordinal(item, index)}${known(item.user_turn) ? ` · Turn ${item.user_turn}` : ""}`);
  }

  function stepRequest(delta) {
    if (state.sessionLoading) return;
    const index = state.session.items.findIndex((item) => item.request_id === state.requestId);
    const next = state.session.items[index + delta];
    if (next) selectRequest(next.request_id);
    else if (index >= 0) loadSessionPage(Math.max(0, state.session.offset + delta * 100), delta > 0 ? "first" : "last");
  }

  async function loadRequestLocation(id, epoch, version) {
    if (metadata(id)) return;
    const context = await api(`/api/requests/${encodeURIComponent(id)}/location?traffic=${state.traffic}`);
    if (epoch !== state.epoch || version !== state.detailVersion || id !== state.requestId) return;
    const thread = context.thread;
    state.traffic = context.traffic || state.traffic;
    state.threadId = thread.thread_id;
    state.threadInfo = thread;
    state.threadOffset = context.thread_offset;
    state.expanded = true;
    state.collapsedTurns.clear();
    state.sessionLoading = true;
    state.treeVersion += 1;
    state.session = { items: [], total: thread.requests, offset: context.request_offset, limit: 100 };
    renderTree();
    const [threads, session] = await Promise.all([
      api(threadsPath(context.thread_offset)),
      api(sessionPath(thread.thread_id, context.request_offset)),
    ]);
    if (epoch !== state.epoch || version !== state.detailVersion || id !== state.requestId) return;
    state.threads = threads;
    state.session = session;
    state.sessionLoading = false;
    updateFilterOptions();
    renderTree(); renderSession(); updateIterationNavigation();
  }

  async function selectRequest(id, { keepSidebar = false, background = false, historyMode = "push" } = {}) {
    if (!validRequestId(id)) return;
    const epoch = state.epoch;
    const version = ++state.detailVersion;
    state.requestId = id;
    if (!background) writeLocation(requestHash(id), historyMode);
    $("copy-request-link").disabled = false;
    $("copy-request-link").textContent = "Copy link";
    $("request-link").hidden = true;
    $("request-link").value = "";
    text("copy-link-status", "");
    if (!keepSidebar) toggleSidebar(false);
    renderTree();
    $("session-tree").querySelector(".iteration-button.selected")?.scrollIntoView({ block: "nearest" });
    if (state.detail?.request_id === id && metadata(id)) { if (!background) showView("request"); updateIterationNavigation(); return; }
    state.detail = null;
    if (background) state.inspectorView = "request";
    else showView("request");
    text("request-title", "Loading request…");
    text("request-id", shortId(id));
    $("request-id").title = id;
    text("request-provider", "");
    text("request-session", metadata(id) ? shortId(state.threadId) : "Locating session…");
    $("request-session").disabled = !metadata(id);
    text("request-ordinal", "Iteration");
    text("request-started", "");
    text("request-endpoint", "");
    text("request-status", "");
    text("conversation-count", "");
    text("request-payload", "Loading request…");
    for (const target of ["request-strip", "request-metric-notes", "conversation-content", "conversation-notices", "payload-notices", "request-metrics"]) $(target).replaceChildren();
    for (const tab of ["conversation", "payload", "metrics"]) $("panel-" + tab).scrollTop = 0;
    updateIterationNavigation();
    try {
      const [item] = await Promise.all([
        api(`/api/requests/${encodeURIComponent(id)}`),
        loadRequestLocation(id, epoch, version),
      ]);
      if (epoch !== state.epoch || version !== state.detailVersion || id !== state.requestId) return;
      state.detail = item;
      renderDetail(item, true);
    } catch (error) {
      if (epoch !== state.epoch || version !== state.detailVersion) return;
      if (error.status === 401) { clearLocalSession(); return; }
      state.sessionLoading = false;
      state.detail = null;
      text("request-title", "Request unavailable");
      const message = error.status === 404 ? "This request is no longer retained or does not exist. Older requests are removed to enforce the storage cap. Global aggregate statistics remain available in Stats." : "Could not load this request. Select it again to retry.";
      if (!metadata(id)) {
        text("request-session", error.status === 404 ? "No retained session" : "Session unavailable");
        $("request-session").disabled = true;
      }
      $("conversation-content").replaceChildren(element("p", "body-notice", message));
      text("request-payload", message);
      $("request-metrics").replaceChildren(element("p", "body-notice", message));
      renderTree(); updateIterationNavigation();
    }
  }

  function setTab(name, focus = false) {
    state.tab = name;
    for (const tab of ["conversation", "payload", "metrics"]) {
      const selected = name === tab;
      $("tab-" + tab).setAttribute("aria-selected", String(selected));
      $("tab-" + tab).tabIndex = selected ? 0 : -1;
      $("panel-" + tab).hidden = !selected;
    }
    if (focus) $("tab-" + name).focus();
  }

  function bodyNotices(item) {
    const nodes = [];
    if (item.body_truncated) nodes.push(element("p", "body-notice", "Request body truncated to the history size limit. This is a partial capture."));
    if (item.body_omitted_reason || item.request_body == null) nodes.push(element("p", "body-notice", item.body_omitted_reason ? `Request body omitted: ${item.body_omitted_reason}` : "No request body retained."));
    return nodes;
  }

  function metricsNotes(item) {
    const notes = [];
    if (item.usage_applicable === false) return ["Token usage does not apply to this request."];
    if (item.outcome === "active") return ["Token usage and cost are updated when the request completes."];
    const usageReasons = {
      usage_missing: "Upstream response did not report complete token usage.",
      malformed_response: "Response data could not be fully parsed for metrics.",
      unsupported_encoding: "Response compression is not supported by the metrics observer.",
      observation_limit: "Response exceeded metrics observation limits; usage may be incomplete.",
      observer_error: "Metrics observation failed for this request.",
    };
    if (usageReasons[item.metrics_unavailable_reason]) notes.push(usageReasons[item.metrics_unavailable_reason]);
    else if (!known(item.input_tokens) || !known(item.output_tokens)) notes.push("Token usage was not reported or captured for this request.");
    const costReasons = {
      pricing_disabled: "API cost estimation is disabled.",
      subscription: "No API-price estimate was recorded for this older subscription request.",
      usage_incomplete: "API cost estimation requires complete reported token usage.",
      unsupported_costs: "This request's billing could not be estimated reliably.",
      unsupported_service_tier: "API pricing for this service tier is unavailable.",
      model_missing: "No model was captured to match API pricing.",
      provider_unmapped: "No API pricing mapping exists for this provider.",
      catalog_unavailable: "The API pricing catalog is unavailable.",
      model_unpriced: "The API pricing catalog has no verified price for this model.",
      unsupported_rates: "This API pricing rate format is not supported.",
    };
    if (!known(item.cost_usd)) {
      const reason = item.cost_unavailable_reason;
      if (reason !== "usage_incomplete" || !notes.length) notes.push(costReasons[reason] || "No reliable API cost estimate is available for this provider, model and reported usage.");
    }
    if (apiEquivalent(item)) notes.push(`API-price equivalent from ${item.cost_source === "custom_api_equivalent" ? "configured API" : "LiteLLM standard API"} text-token rates. Excludes extra media and hosted-tool charges; not a ChatGPT subscription charge.`);
    if (item.response_format === "json" && !known(item.ttft_ms) && !known(item.tps)) notes.push("No streaming output was observed; TTFT and TPS are unavailable.");
    return notes;
  }

  function renderDetail(item, renderBody) {
    const record = metadata(item.request_id);
    text("request-title", item.model || (item.usage_applicable === false ? "HTTP request" : "Unknown model"));
    text("request-id", shortId(item.request_id));
    $("request-id").title = item.request_id;
    text("request-provider", item.provider || "Unknown provider");
    text("request-session", shortId(item.thread_id || state.threadId));
    $("request-session").disabled = !(item.thread_id || state.threadId);
    text("request-started", date(item.started_at, true));
    text("request-endpoint", `${item.method || ""} ${item.path || ""}`);
    $("request-status").replaceChildren(badge(item));
    if (!record) text("request-ordinal", `Request ${shortId(item.request_id)}`);
    updateIterationNavigation();
    $("request-strip").replaceChildren();
    const tokenUsage = item.usage_applicable === false ? "Not applicable" : `${count(item.input_tokens)} in · ${count(item.output_tokens)} out`;
    const costLabel = apiEquivalent(item) ? "Est. API cost" : "Est. cost";
    const metrics = [["Latency", duration(item.duration_ms)], ["TTFT", duration(item.ttft_ms)], ["Tokens", tokenUsage], [costLabel, cost(item.cost_usd)], ["Est. TPS", speed(item.tps)], ["Redactions", count(item.redactions || 0)]];
    if (known(item.cached_input_tokens)) metrics.push(["Cached tokens", count(item.cached_input_tokens)]);
    if (known(item.reasoning_tokens)) metrics.push(["Reasoning tokens", count(item.reasoning_tokens)]);
    for (const [label, value] of metrics) {
      const metric = element("span", "strip-metric");
      metric.append(element("span", "", label), element("strong", "", value));
      $("request-strip").append(metric);
    }
    $("request-metric-notes").replaceChildren(...metricsNotes(item).map((note) => element("p", "context-note", note)));
    const scroll = $("panel-metrics").scrollTop;
    renderMetrics(item);
    $("panel-metrics").scrollTop = scroll;
    if (renderBody) {
      $("conversation-notices").replaceChildren(...bodyNotices(item));
      $("payload-notices").replaceChildren(...bodyNotices(item));
      text("payload-size", typeof item.request_body === "string" ? `${count(new TextEncoder().encode(item.request_body).length)} bytes retained` : "No body retained");
      text("request-payload", item.request_body == null ? "No request body retained." : pretty(item.request_body));
      renderConversation(item);
    }
    setTab(state.tab);
  }

  function structured(label, value) {
    const details = element("details", "structured-block");
    details.append(element("summary", "", label));
    let rendered = false;
    details.addEventListener("toggle", () => {
      if (details.open && !rendered) { rendered = true; details.append(element("pre", "code-block", pretty(value))); }
    });
    return details;
  }

  function toolBlock(name, argumentsValue, callId) {
    const block = element("div", "tool-block");
    const header = element("div", "tool-heading");
    header.append(element("strong", "", name || "Tool call"));
    if (callId) header.append(element("span", "", `call ${callId}`));
    block.append(header, element("pre", "code-block", pretty(argumentsValue)));
    return block;
  }

  function renderContent(container, content, depth = 0) {
    if (depth >= 8) {
      container.append(structured("Nested content · open captured structure", content));
      return;
    }
    if (typeof content === "string") {
      container.append(element("pre", "message-text", content));
      return;
    }
    if (!Array.isArray(content)) {
      if (content != null) container.append(structured("Structured content", content));
      return;
    }
    for (const part of content.slice(0, 100)) {
      if (typeof part === "string") { container.append(element("pre", "message-text", part)); continue; }
      if (!part || typeof part !== "object") continue;
      const type = typeof part.type === "string" ? part.type : "content";
      if (typeof part.text === "string") container.append(element("pre", "message-text", part.text));
      else if (typeof part.text?.value === "string") container.append(element("pre", "message-text", part.text.value));
      else if (type === "tool_use" || type === "function_call") container.append(toolBlock(part.name, part.input ?? part.arguments, part.id ?? part.call_id));
      else if (type === "tool_result" || type === "function_call_output") {
        const block = element("div", "tool-block");
        block.append(element("div", "tool-heading", `Tool output${part.tool_use_id || part.call_id ? ` · ${part.tool_use_id || part.call_id}` : ""}`));
        const body = element("div", "message-body"); renderContent(body, part.content ?? part.output, depth + 1); block.append(body); container.append(block);
      } else if (typeof part.refusal === "string") container.append(element("pre", "message-text", part.refusal));
      else container.append(structured(`${type.replaceAll("_", " ")} · captured metadata only`, part));
    }
    if (content.length > 100) container.append(structured(`${content.length} content blocks · first 100 shown above; open complete structure`, content));
  }

  function hasContent(content, depth = 0) {
    if (typeof content === "string") return content.trim().length > 0;
    if (content == null) return false;
    if (depth >= 8) return true;
    if (!Array.isArray(content)) return typeof content !== "object" || Object.keys(content).length > 0;
    return content.length > 100 || content.some((part) => {
      if (typeof part === "string") return part.trim().length > 0;
      if (!part || typeof part !== "object") return false;
      if (typeof part.text === "string") return part.text.trim().length > 0;
      if (typeof part.text?.value === "string") return part.text.value.trim().length > 0;
      if (typeof part.refusal === "string") return part.refusal.trim().length > 0;
      if (["tool_result", "function_call_output"].includes(part.type)) return hasContent(part.content ?? part.output, depth + 1) || !!(part.tool_use_id || part.call_id);
      return Object.keys(part).some((key) => key !== "type");
    });
  }

  function visibleMessage(message) {
    if (["function_call", "custom_tool_call", "function_call_output", "custom_tool_call_output"].includes(message.type)) return true;
    if (message.role === "tool" && message.tool_call_id) return true;
    if (hasContent(message.content ?? message.summary)) return true;
    return (Array.isArray(message.tool_calls) && message.tool_calls.length > 0) || (message.tool_calls != null && !Array.isArray(message.tool_calls)) || message.function_call != null;
  }

  function messageNode(message, index) {
    const type = typeof message.type === "string" ? message.type : "message";
    const toolOutput = ["function_call_output", "custom_tool_call_output"].includes(type) || message.role === "tool";
    const toolCall = ["function_call", "custom_tool_call"].includes(type);
    const role = toolOutput ? "tool" : toolCall ? "assistant" : (typeof message.role === "string" ? message.role : type === "reasoning" ? "reasoning" : "message");
    const safeRole = ["user", "assistant", "tool", "system", "developer"].includes(role) ? role : "other";
    const card = element("details", `message ${safeRole}`);
    const output = message.output ?? message.content;
    const emptyToolOutput = toolOutput && !hasContent(output);
    card.open = !["system", "developer"].includes(role) && !emptyToolOutput;
    const header = element("summary");
    header.append(element("span", "message-role", toolOutput ? "Tool output" : toolCall ? "Tool call" : role), element("span", "message-kind", message.name || (emptyToolOutput ? "Empty result" : type === "reasoning" ? "captured reasoning item" : "")), element("span", "message-index", `#${index + 1}`));
    card.append(header);
    const body = element("div", "message-body");
    let rendered = false;
    function fill() {
      if (rendered) return;
      rendered = true;
      if (toolCall) body.append(toolBlock(message.name, message.arguments ?? message.input, message.call_id ?? message.id));
      else if (toolOutput) {
        const callId = message.call_id || message.tool_call_id;
        if (callId) body.append(element("p", "context-note", `Tool call ${callId}`));
        renderContent(body, output);
      } else {
        if (message.tool_call_id) body.append(element("p", "context-note", `Tool call ${message.tool_call_id}`));
        renderContent(body, message.content ?? message.summary);
        if (Array.isArray(message.tool_calls)) {
          for (const call of message.tool_calls.slice(0, 100)) {
            if (call && typeof call === "object" && !Array.isArray(call)) body.append(toolBlock(call.function?.name || call.name, call.function?.arguments ?? call.arguments ?? call.input, call.id));
            else body.append(structured("Unrecognized tool call", call));
          }
          if (message.tool_calls.length > 100) body.append(structured(`${message.tool_calls.length} tool calls · first 100 shown above; open complete structure`, message.tool_calls));
        } else if (message.tool_calls != null) body.append(structured("Unrecognized tool_calls value", message.tool_calls));
        if (message.function_call && typeof message.function_call === "object") body.append(toolBlock(message.function_call.name, message.function_call.arguments));
        else if (message.function_call != null) body.append(structured("Unrecognized function_call value", message.function_call));
      }
      if (!body.childNodes.length) body.append(element("p", "message-empty", "No text content in this captured message."));
      card.append(body);
    }
    if (card.open) fill();
    card.addEventListener("toggle", () => { if (card.open) fill(); });
    return card;
  }

  function renderConversation(item) {
    const container = $("conversation-content");
    container.replaceChildren();
    text("conversation-count", "");
    if (item.request_body == null) return;
    let payload;
    try { payload = JSON.parse(item.request_body); } catch {
      container.append(element("p", "body-notice", "Captured body is not complete JSON. Open Payload to inspect the retained text."));
      return;
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      container.append(element("p", "body-notice", "No conversation-shaped fields found. Open Payload to inspect this request."));
      return;
    }
    const prefix = [];
    if (typeof payload.instructions === "string") prefix.push({ role: "system", content: payload.instructions, name: "Instructions" });
    if (typeof payload.system === "string" || Array.isArray(payload.system)) prefix.push({ role: "system", content: payload.system });
    let messages = [];
    if (Array.isArray(payload.messages)) messages = payload.messages;
    else if (Array.isArray(payload.input)) messages = payload.input;
    else if (typeof payload.input === "string") prefix.push({ role: "user", content: payload.input });
    function* capturedMessages(visibleOnly = true) {
      for (const source of [messages, prefix]) {
        for (let index = source.length - 1; index >= 0; index -= 1) {
          const message = source[index];
          if (message && typeof message === "object" && !Array.isArray(message) && (!visibleOnly || visibleMessage(message))) yield { message, index: source === messages ? prefix.length + index : index };
        }
      }
    }
    let total = 0;
    for (const message of capturedMessages()) total += 1;
    let captured = 0;
    for (const message of capturedMessages(false)) captured += 1;
    if (captured > total) container.append(element("p", "context-note", `${count(captured - total)} entries without readable content omitted. Complete captured data remains in Payload.`));
    text("conversation-count", total ? count(total) : "");
    if (payload.previous_response_id) container.append(element("p", "body-notice", "Incremental Responses request. Only history present in this payload is shown; earlier response content is not stored."));
    if (!total) container.append(element("p", "body-notice", "No conversation messages found. Open Payload to inspect this request."));
    const iterator = capturedMessages();
    let rendered = 0;
    const paging = element("div", "conversation-paging");
    const note = element("p", "context-note");
    const more = button("quiet", "Load more messages", () => appendBatch());
    more.id = "conversation-more";
    paging.append(note, more);
    container.append(paging);
    function appendBatch() {
      const fragment = document.createDocumentFragment();
      for (let batch = 0; batch < 50; batch += 1) {
        const entry = iterator.next();
        if (entry.done) break;
        fragment.append(messageNode(entry.value.message, entry.value.index));
        rendered += 1;
      }
      container.insertBefore(fragment, paging);
      note.textContent = `Showing ${count(rendered)} of ${count(total)} captured messages.`;
      more.textContent = `Load next ${Math.min(50, total - rendered)} messages`;
      more.hidden = rendered >= total;
      paging.hidden = total <= 50;
    }
    appendBatch();
    if (Array.isArray(payload.tools) && payload.tools.length) container.append(structured(`${payload.tools.length} tool definitions in request`, payload.tools));
  }

  function field(grid, label, value, mono = false) {
    const node = element("div", "metric-field");
    node.append(element("dt", "", label), element("dd", mono ? "mono" : "", value ?? "—"));
    grid.append(node);
  }

  function metricsSection(title, fields) {
    const section = element("section", "metrics-section");
    const grid = element("dl", "metrics-grid");
    section.append(element("h2", "", title), grid);
    for (const [label, value, mono] of fields) field(grid, label, value, mono);
    return section;
  }

  function rulesList(hits) {
    const list = element("div", "rule-list");
    const entries = Object.entries(hits || {}).sort((a, b) => b[1] - a[1]);
    for (const [rule, hits] of entries) {
      const row = element("div", "rule-row");
      row.append(element("span", "rule-name", rule), element("span", "rule-count", count(hits)));
      list.append(row);
    }
    if (!entries.length) list.append(element("p", "context-note", "No redaction matches recorded."));
    return list;
  }

  function renderMetrics(item) {
    const root = $("request-metrics");
    root.replaceChildren();
    for (const note of metricsNotes(item)) root.append(element("p", "body-notice", note));
    root.append(metricsSection("Timing", [["Total duration", duration(item.duration_ms)], ["Time to first token", duration(item.ttft_ms)], ["Generation time", duration(item.generation_ms)], ["Estimated tokens / second", speed(item.tps)], ["Streaming", item.stream ? "Yes" : "No"], ["Outcome", statusLabel(item)]]));
    root.append(element("p", "context-note", "TTFT measures request start to first output content. TPS estimates (output tokens − 1) / time between first and last output. Providers batch tokens, so this is an estimate."));
    root.append(metricsSection("Token usage", [["Input tokens", count(item.input_tokens)], ["Output tokens", count(item.output_tokens)], ["Total tokens", count(item.total_tokens)], ["Cached input tokens", count(item.cached_input_tokens)], ["Cache write tokens", count(item.cache_write_tokens)], ["Reasoning tokens", count(item.reasoning_tokens)], ["Usage source", item.usage_source], ["Token usage applicable", item.usage_applicable === true ? "Yes" : item.usage_applicable === false ? "No" : "Unknown"], ["Observed response format", ({ json: "JSON", sse: "Event stream", unknown: "Unknown" })[item.response_format] || "Unknown"]]));
    const equivalent = apiEquivalent(item);
    const priceSource = item.cost_source === "custom_api_equivalent" ? "Configured API pricing" : equivalent ? "LiteLLM API pricing" : item.cost_source;
    root.append(metricsSection(equivalent ? "Estimated API-price equivalent" : "Estimated cost", [["Cost (USD)", cost(item.cost_usd)], ["Cost source", priceSource], ["Pricing model", item.pricing_model], ["Pricing snapshot", item.pricing_as_of], ["Provider", item.provider]]));
    if (item.pricing_rates) root.append(structured("Pricing rates used for this estimate", item.pricing_rates));
    const redactions = element("section", "metrics-section");
    redactions.append(element("h2", "", `${count(item.redactions || 0)} redaction matches`), element("p", "context-note", "Rule matches, not unique credentials. Categories only; secret values are not included in these counts."), rulesList(item.rule_hits));
    root.append(redactions);
    const record = metadata(item.request_id) || item;
    const identity = metricsSection("Request identity", [["Request ID", item.request_id, true], ["Session ID", item.thread_id, true], ["Session grouping", item.thread_source], ["Started", date(item.started_at, true)], ["Completed", date(item.completed_at, true)], ["Endpoint", `${item.method || ""} ${item.path || ""}`, true]]);
    if (known(record.user_turn)) field(identity.querySelector("dl"), "User turn", `${record.user_turn}${record.turn_source === "inferred" ? " · inferred" : ""}`);
    if (known(record.message_count)) field(identity.querySelector("dl"), "Captured message count", count(record.message_count));
    const parent = item.parent_request_id || record.parent_request_id;
    if (parent) {
      const cell = element("div", "metric-field");
      const value = element("dd");
      value.append(button("table-button", `Open parent ${shortId(parent)}`, () => selectRequest(parent)));
      cell.append(element("dt", "", "Parent request"), value);
      identity.querySelector("dl").append(cell);
    }
    root.append(identity);
  }

  function renderSummary(data) {
    state.summary = data;
    const scroll = $("overview-view").querySelector(".scroll-pane").scrollTop;
    const lifetime = state.days === 36500 && data.lifetime_totals;
    const totals = lifetime || data.totals;
    const requests = totals.requests || 0;
    const unknownCost = totals.unknown_cost_requests || 0;
    const unknownUsage = totals.unknown_usage_requests || 0;
    const applicableRequests = known(totals.usage_applicable_requests) ? totals.usage_applicable_requests : requests;
    const coverageLabel = totals.usage_applicability_unknown_requests > 0 || !known(totals.usage_applicable_requests) ? "recorded requests" : "LLM requests";
    const pricedRequests = totals.cost_usd_known_requests || 0;
    const storage = data.storage || {};
    const dropped = storage.dropped_writes || 0;
    const errors = storage.write_errors || 0;
    $("capture-warning").hidden = !dropped && !errors;
    if (dropped || errors) {
      const warning = `Lifetime: ${count(dropped)} writes dropped, ${count(errors)} persistence errors. Requests and metrics may be incomplete. Coverage describes recorded requests only.`;
      if ($("capture-warning-text").textContent !== warning) text("capture-warning-text", warning);
    }
    const metrics = [
      ["Recorded requests", count(requests), `${count(totals.successes || 0)} successful · ${count(totals.errors || 0)} errors`],
      ["Total tokens", tokens(totals.total_tokens), `${count(unknownUsage)} ${coverageLabel} with unknown token usage`],
      ["Estimated API cost · USD", cost(totals.cost_usd), `Cost recorded for ${count(pricedRequests)}/${count(applicableRequests)} ${coverageLabel}${unknownCost ? " · partial total" : ""}. Includes API-price equivalents for subscription requests.`],
      ["Average time to first token", duration(totals.avg_ttft_ms), "Observed output streams"],
      ["Average estimated TPS", known(totals.avg_tps) ? `${speed(totals.avg_tps)}/s` : "—", "After first output token"],
      ["Redaction matches", count(totals.redactions || 0), `${count(totals.redacted_requests || 0)} requests · not unique credentials`],
    ];
    $("overview-metrics").replaceChildren();
    for (const [label, value, note] of metrics) {
      const cell = element("div", "overview-metric");
      cell.append(element("p", "", label), element("strong", "", value), element("span", "", note));
      $("overview-metrics").append(cell);
    }
    $("overview-tokens").replaceChildren();
    for (const [label, value] of [["Input", totals.input_tokens], ["Output", totals.output_tokens], ["Reasoning (part of output)", totals.reasoning_tokens], ["Cached input", totals.cached_input_tokens], ["Cache writes", totals.cache_write_tokens]]) field($("overview-tokens"), label, count(value));
    for (const [label, fieldName] of [["Input usage coverage", "input_tokens_known_requests"], ["Output usage coverage", "output_tokens_known_requests"]]) field($("overview-tokens"), label, `${count(totals[fieldName])}/${count(applicableRequests)} ${coverageLabel}`);
    const unknownApplicability = totals.usage_applicability_unknown_requests;
    $("overview-usage-note").hidden = !(unknownApplicability > 0);
    text("overview-usage-note", `Coverage includes ${count(unknownApplicability)} older requests whose LLM usage applicability is unknown. Identified bookkeeping requests are excluded.`);
    $("overview-rules").replaceChildren(rulesList(lifetime ? data.totals.rule_hits : totals.rule_hits));
    $("overview-models").replaceChildren();
    for (const model of data.models || []) {
      const row = element("tr");
      const identity = element("td");
      identity.append(element("span", "model-cell", model.model || "Unknown model"), element("span", "cell-subtitle", model.provider || "Unknown provider"));
      const modelApplicable = known(model.usage_applicable_requests) ? model.usage_applicable_requests : model.requests;
      const modelCoverage = element("td", "", `${count(model.cost_usd_known_requests)}/${count(modelApplicable)}`);
      modelCoverage.title = model.usage_applicability_unknown_requests > 0 || !known(model.usage_applicable_requests) ? "Recorded requests with cost; older request applicability is unknown." : "LLM requests with recorded cost; bookkeeping requests excluded.";
      row.append(identity, element("td", "", count(model.requests)), element("td", "", tokens(model.total_tokens)), element("td", "", cost(model.cost_usd)), modelCoverage);
      $("overview-models").append(row);
    }
    const used = known(storage.detail_bytes) ? `${decimal.format(storage.detail_bytes / 1048576)} MiB` : "—";
    const totalUsed = known(storage.total_bytes) ? `${decimal.format(storage.total_bytes / 1048576)} MiB` : used;
    const cap = known(storage.max_database_bytes) ? ` / ${decimal.format(storage.max_database_bytes / 1048576)} MiB cap` : "";
    text("retention-note", `${count(storage.retained_requests || 0)} retained requests · SQLite ${totalUsed}${cap}`);
    const pruned = known(storage.pruned_requests) ? ` ${count(storage.pruned_requests)} old requests removed.` : "";
    const aggregateNote = storage.pruned_aggregate_rows > 0 ? ` Daily, model and redaction breakdowns cover retained aggregate history; ${count(storage.pruned_aggregate_rows)} old aggregate rows were removed. Lifetime totals remain available under All time.` : " Lifetime totals survive request eviction.";
    $("aggregate-history-note").hidden = !(storage.pruned_aggregate_rows > 0);
    text("aggregate-history-note", "Older daily, model and redaction breakdowns were removed to enforce the SQLite cap. Period statistics cover retained aggregate history. Select All time for preserved lifetime totals.");
    text("overview-storage", `SQLite storage: ${totalUsed}${cap}. Request details: ${used}. Aggregate statistics: ${known(storage.stats_bytes) ? `${decimal.format(storage.stats_bytes / 1048576)} MiB` : "unknown size"}.${pruned}${aggregateNote} Missing usage and pricing remain unknown.`);
    const trendRequests = (data.daily || []).reduce((total, day) => total + (day.requests || 0), 0);
    renderTrend(data.daily || [], trendRequests);
    $("overview-view").querySelector(".scroll-pane").scrollTop = scroll;
  }

  function renderTrend(daily, total) {
    if (daily.length) {
      const byDay = new Map(daily.map((day) => [day.day, day]));
      const today = new Date().toISOString().slice(0, 10);
      const end = Date.parse(`${today}T00:00:00Z`);
      const start = state.days === 36500 ? Date.parse(`${daily[0].day}T00:00:00Z`) : end - (state.days - 1) * 86400000;
      const continuous = [];
      for (let timestamp = start; timestamp <= end; timestamp += 86400000) {
        const day = new Date(timestamp).toISOString().slice(0, 10);
        continuous.push(byDay.get(day) || { day, requests: 0 });
      }
      daily = continuous;
    }
    const chart = $("trend-chart"); chart.replaceChildren();
    text("trend-total", `${count(total)} requests`);
    text("trend-start", daily.length ? daily[0].day : "—");
    text("trend-end", daily.length ? daily[daily.length - 1].day : "—");
    if (!daily.length || !daily.some((day) => day.requests > 0)) {
      chart.append(element("span", "chart-empty", "No traffic in this period"));
      chart.setAttribute("aria-label", "No requests recorded in this period");
      return;
    }
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 720 140"); svg.setAttribute("preserveAspectRatio", "none"); svg.setAttribute("aria-hidden", "true");
    const maximum = daily.reduce((peak, day) => Math.max(peak, day.requests || 0), 1);
    const points = daily.map((day, index) => [daily.length === 1 ? 360 : index * 720 / (daily.length - 1), 136 - (day.requests || 0) / maximum * 120]);
    const path = points.map(([x, y], index) => `${index ? "L" : "M"}${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
    const area = document.createElementNS(ns, "path"); area.setAttribute("d", `${path} L${points[points.length - 1][0]},140 L${points[0][0]},140 Z`); area.setAttribute("class", "trend-area");
    const line = document.createElementNS(ns, "path"); line.setAttribute("d", path); line.setAttribute("class", "trend-line");
    svg.append(area, line); chart.append(svg);
    chart.setAttribute("aria-label", `${count(total)} requests from ${daily[0].day} to ${daily[daily.length - 1].day}. Peak ${count(maximum)} per day.`);
  }

  async function refresh() {
    if (!state.authenticated || state.locking || $("dashboard").hidden) return;
    if (state.refreshing) { state.refreshAgain = true; return; }
    state.refreshing = true;
    const epoch = state.epoch;
    const offset = state.threadOffset;
    const treeVersion = state.treeVersion;
    const threadId = state.threadId;
    const sessionOffset = state.session.offset;
    const days = state.days;
    const traffic = state.traffic;
    try {
      const [summary, threads, session] = await Promise.all([
        api(`/api/summary?days=${days}`),
        api(threadsPath(offset)),
        threadId && !state.sessionLoading ? api(sessionPath(threadId, sessionOffset)) : Promise.resolve(null),
      ]);
      if (epoch !== state.epoch) return;
      if (days === state.days) renderSummary(summary);
      if (traffic === state.traffic && offset === state.threadOffset) { state.threads = threads; updateFilterOptions(); }
      if (session && treeVersion === state.treeVersion && threadId === state.threadId && !state.sessionLoading) state.session = session;
      renderTree(); renderSession(); updateIterationNavigation();
      if (!state.lockError) $("load-error").hidden = true;
      text("live-status", "Online");
      $("live-status").classList.remove("stale");
      text("updated-at", `Updated ${new Date().toLocaleTimeString()}`);
      if (!state.initialized && state.threads.items.length) {
        state.initialized = true;
        await selectSession(state.threads.items[0], { latest: true, keepSidebar: true });
      } else if (!state.initialized && state.view !== "overview") {
        showEmpty(state.traffic === "inference" ? "Waiting for inference requests" : "Waiting for requests", state.traffic === "inference" ? "Inference sessions appear here as requests pass through the proxy. Ancillary calls remain available under All HTTP traffic." : "Sessions appear here when traffic passes through the proxy with history enabled.");
      }
      if (state.detail?.outcome === "active") {
        const id = state.requestId;
        const version = state.detailVersion;
        const item = await api(`/api/requests/${encodeURIComponent(id)}`);
        if (epoch !== state.epoch || version !== state.detailVersion || id !== state.requestId) return;
        const bodyChanged = item.request_body !== state.detail?.request_body || item.body_truncated !== state.detail?.body_truncated || item.body_omitted_reason !== state.detail?.body_omitted_reason;
        state.detail = item;
        const positions = ["conversation", "payload", "metrics"].map((tab) => $("panel-" + tab).scrollTop);
        renderDetail(item, bodyChanged);
        ["conversation", "payload", "metrics"].forEach((tab, index) => { $("panel-" + tab).scrollTop = positions[index]; });
      }
    } catch (error) {
      if (epoch !== state.epoch) return;
      if (error.status === 401) { clearLocalSession(); return; }
      if (!state.lockError) text("load-error", "Activity refresh failed. Displayed values may be stale. Retrying automatically.");
      $("load-error").hidden = false;
      text("live-status", "Refresh delayed");
      $("live-status").classList.add("stale");
    } finally {
      state.refreshing = false;
      if (state.refreshAgain) { state.refreshAgain = false; refresh(); }
    }
  }

  $("signin-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("signin-submit").disabled = true;
    $("signin-error").hidden = true;
    let token = $("dashboard-token").value;
    const epoch = ++state.epoch;
    $("retry-session").hidden = true;
    $("retry-session").disabled = true;
    try {
      const session = await api("/api/session", { method: "POST", bearerToken: token });
      token = "";
      $("dashboard-token").value = "";
      if (epoch !== state.epoch) return;
      await activateSession(session, epoch);
    } catch (error) {
      if (epoch !== state.epoch) return;
      text("signin-error", error.status ? error.message : "Could not connect to the dashboard server.");
      $("signin-error").hidden = false;
    } finally {
      token = "";
      if (epoch === state.epoch) {
        $("signin-submit").disabled = false;
        $("retry-session").disabled = false;
      }
    }
  });
  $("signout").addEventListener("click", endSession);
  $("retry-session").addEventListener("click", restoreSession);
  $("session-toggle").addEventListener("click", () => toggleSidebar(!$("workbench").classList.contains("sidebar-open")));
  $("sidebar-backdrop").addEventListener("click", () => toggleSidebar(false));
  $("refresh-now").addEventListener("click", refresh);
  $("thread-search").addEventListener("input", renderTree);
  for (const name of ["status", "provider", "model"]) $("filter-" + name).addEventListener("change", renderTree);
  $("filter-traffic").addEventListener("change", () => {
    state.traffic = $("filter-traffic").value;
    state.treeVersion += 1;
    state.detailVersion += 1;
    state.routeVersion += 1;
    state.threadId = state.requestId = state.detail = state.threadInfo = null;
    state.threads = { items: [], total: 0 };
    state.session = { items: [], total: 0, offset: 0, limit: 100 };
    state.sessionLoading = false;
    state.threadOffset = 0;
    state.collapsedTurns.clear();
    state.initialized = false;
    for (const name of ["status", "provider", "model"]) $("filter-" + name).value = "";
    writeLocation("requests");
    showEmpty("Loading activity", "Reading local request history…");
    renderTree();
    refresh();
  });
  $("clear-selection").addEventListener("click", () => {
    state.requestId = state.detail = null;
    state.detailVersion += 1;
    writeLocation("requests");
    showView("session"); renderSession(); renderTree();
  });
  $("copy-request-link").addEventListener("click", async () => {
    const id = state.requestId;
    if (!validRequestId(id)) return;
    const link = requestLink(id);
    try {
      await navigator.clipboard.writeText(link);
      if (state.requestId !== id || !state.authenticated) return;
      $("copy-request-link").textContent = "Copied";
      text("copy-link-status", "Request link copied.");
    } catch {
      if (state.requestId !== id || !state.authenticated) return;
      const field = $("request-link");
      field.value = link;
      field.hidden = false;
      field.focus(); field.select();
      text("copy-link-status", "Copy this selected request link.");
    }
  });
  $("threads-prev").addEventListener("click", () => { state.threadOffset = Math.max(0, state.threadOffset - 50); refresh(); });
  $("threads-next").addEventListener("click", () => { state.threadOffset += 50; refresh(); });
  $("session-prev").addEventListener("click", () => changeSessionPage(Math.max(0, state.session.offset - 100)));
  $("session-next").addEventListener("click", () => changeSessionPage(state.session.offset + 100));
  $("request-prev").addEventListener("click", () => stepRequest(-1));
  $("request-next").addEventListener("click", () => stepRequest(1));
  $("request-session").addEventListener("click", () => { writeLocation("requests"); showView("session"); renderSession(); renderTree(); });
  $("nav-overview").addEventListener("click", () => {
    writeLocation("stats");
    state.detailVersion += 1;
    state.sessionLoading = false;
    showView("overview"); toggleSidebar(false); renderTree();
  });
  $("nav-inspector").addEventListener("click", () => {
    if (state.inspectorView === "request" && state.requestId) selectRequest(state.requestId);
    else { writeLocation("requests"); showView(state.inspectorView); renderTree(); }
  });
  window.addEventListener("popstate", () => navigateLocation());
  window.addEventListener("hashchange", () => navigateLocation());
  $("days").addEventListener("change", () => { state.days = Number($("days").value); refresh(); });
  const tabs = ["conversation", "payload", "metrics"];
  for (const tab of tabs) {
    $("tab-" + tab).addEventListener("click", () => setTab(tab));
    $("tab-" + tab).addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (tabs.indexOf(tab) + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      setTab(tabs[next], true);
    });
  }
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") toggleSidebar(false);
    if (event.key === "/" && state.authenticated && !event.ctrlKey && !event.metaKey && !event.altKey && !["INPUT", "TEXTAREA", "SELECT"].includes(event.target.tagName) && !event.target.isContentEditable) {
      event.preventDefault(); toggleSidebar(true); $("thread-search").focus();
    }
  });
  setInterval(() => { if (!document.hidden) refresh(); }, 5000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  clearLegacyTokens();
  restoreSession();
})();
