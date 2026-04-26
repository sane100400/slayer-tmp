const OPENAI_API_KEY = "sk-proj-abc123def456ghi789012345";
const WEBHOOK_SECRET = "whsec_abcdef1234567890123456789012";

async function callAI(prompt: string) {
  const response = await fetch("https://api.openai.com/v1/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
  });
  return response.json();
}

async function handleWebhook(req: any) {
  const result = await fetch(req.body.callbackUrl);
  return result.json();
}
