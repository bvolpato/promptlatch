(() => {
  document.documentElement.classList.add("js");

  const copyText = async (button, text) => {
    const label = button.textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    button.disabled = true;
    window.setTimeout(() => {
      button.textContent = label;
      button.disabled = false;
    }, 1600);
  };

  for (const button of document.querySelectorAll("[data-copy]")) {
    const source = document.querySelector(button.dataset.copy);
    button.addEventListener("click", () => copyText(button, source.textContent));
  }

  for (const code of document.querySelectorAll("pre > code[data-lang]")) {
    const block = document.createElement("div");
    block.className = "code";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.addEventListener("click", () => copyText(button, code.textContent));
    code.parentElement.replaceWith(block);
    block.append(code.parentElement, button);
  }

  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const select = (tab, focus = false) => {
    for (const item of tabs) {
      const selected = item === tab;
      item.setAttribute("aria-selected", String(selected));
      item.tabIndex = selected ? 0 : -1;
      document.getElementById(item.getAttribute("aria-controls")).hidden = !selected;
    }
    if (focus) tab.focus();
  };
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => select(tab));
    tab.addEventListener("keydown", (event) => {
      const next = {
        ArrowRight: (index + 1) % tabs.length,
        ArrowLeft: (index - 1 + tabs.length) % tabs.length,
        Home: 0,
        End: tabs.length - 1,
      }[event.key];
      if (next === undefined) return;
      event.preventDefault();
      select(tabs[next], true);
    });
  });
  if (tabs.length) select(tabs[0]);
})();
