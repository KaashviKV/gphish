document.getElementById("checkButton").addEventListener("click", async function () {
  const url = document.getElementById("urlInput").value.trim();
  const resultText = document.getElementById("resultText");
  const loading = document.getElementById("loading");
  const resultArea = document.getElementById("resultArea");

  let reasonEl = document.getElementById("reasonText");
  if (!reasonEl) {
    reasonEl = document.createElement("div");
    reasonEl.id = "reasonText";
    reasonEl.style.marginTop = "10px";
    reasonEl.style.fontSize = "0.95rem";
    reasonEl.style.color = "#333";
    resultArea.appendChild(reasonEl);
  }

  if (!url) {
    resultText.textContent = "Please enter a valid URL.";
    resultText.classList.remove("result-safe", "result-danger");
    resultText.classList.add("result-danger");
    resultArea.style.display = "block";
    reasonEl.innerHTML = "";
    return;
  }

  // Show loading
  loading.style.display = "block";
  resultArea.style.display = "none";
  resultText.textContent = "";
  reasonEl.innerHTML = "";

  try {
    const response = await fetch("/check_phishing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) throw new Error(`Server error: ${response.status}`);
    const data = await response.json();
    if (data.error) throw new Error(data.error);

    loading.style.display = "none";
    resultArea.style.display = "block";

    if (data.isPhishing) {
      resultText.textContent = "⚠️ The URL appears to be a phishing site!";
      resultText.classList.remove("result-safe");
      resultText.classList.add("result-danger");
    } else {
      resultText.textContent = "✅ The URL appears to be real (no obvious heuristics).";
      resultText.classList.remove("result-danger");
      resultText.classList.add("result-safe");
    }

    // Display reasons as a list
    if (Array.isArray(data.reasons) && data.reasons.length) {
      const escapeHtml = (str) =>
        str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      const items = data.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("");
      reasonEl.innerHTML = `<strong>Reasons:</strong><ul style="text-align:left;margin-top:8px;">${items}</ul>`;
    } else {
      reasonEl.innerHTML = "";
    }
  } catch (error) {
    loading.style.display = "none";
    resultText.textContent = "Oops! Something went wrong. Please try again later.";
    resultText.classList.remove("result-safe");
    resultText.classList.add("result-danger");
    resultArea.style.display = "block";
    reasonEl.innerHTML = "";
    console.error(error);
  }
});
