document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);
  const payload = Object.fromEntries(formData.entries());

  const output = document.getElementById("login-output");

  try {
    const result = await api("/api/login", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    // ✅ SAFE (no XSS)
    output.textContent = JSON.stringify(result, null, 2);

  } catch (error) {
    // ✅ SAFE
    output.textContent = JSON.stringify({ error: error.message }, null, 2);
  }
});
