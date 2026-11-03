const baseUrl = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  const body = await response.json().catch(() => null);

  if (!response.ok) {
    const message =
      body?.error?.message || `Request failed with status ${response.status}.`;
    throw new Error(message);
  }
  return body;
}

export const getHealth = () => request("/health");

export const scanText = (text) =>
  request("/v1/scan", {
    method: "POST",
    body: JSON.stringify({ text }),
  });

export const protectedGenerate = (text, task, signal) =>
  request("/v1/protected-generate", {
    method: "POST",
    body: JSON.stringify({ text, task }),
    signal,
  });
