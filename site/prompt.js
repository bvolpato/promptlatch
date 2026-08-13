const copyButton = document.querySelector("#copy-prompt");
const label = copyButton.querySelector("#copy-prompt-label");
const icon = copyButton.querySelector(".button-icon");
const status = document.querySelector("#copy-prompt-status");

copyButton.addEventListener("click", async () => {
  copyButton.disabled = true;

  try {
    const response = await fetch(copyButton.dataset.promptUrl, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Prompt request failed: ${response.status}`);
    }

    await navigator.clipboard.writeText(await response.text());
    label.textContent = "Copied";
    icon.src = "./icons/check.svg";
    status.textContent = "PromptLatch integration prompt copied.";
  } catch {
    label.textContent = "Copy failed";
    status.textContent = "Prompt could not be copied. Open PROMPT.md from the repository.";
  }

  window.setTimeout(() => {
    label.textContent = "Copy prompt";
    icon.src = "./icons/copy.svg";
    copyButton.disabled = false;
  }, 2400);
});
