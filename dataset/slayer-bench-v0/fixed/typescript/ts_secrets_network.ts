const OPENAI_API_KEY = process.env.OPENAI_API_KEY!;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET!;

const ALLOWED_HOSTS = new Set(['hooks.slack.com', 'api.github.com']);

async function callAI(prompt: string) {
  const response = await fetch("https://api.openai.com/v1/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
  });
  return response.json();
}

async function handleWebhook(req: any) {
  const callbackUrl: string = req.body.callbackUrl;
  const host = new URL(callbackUrl).hostname;
  if (!ALLOWED_HOSTS.has(host)) throw new Error('Forbidden callback URL');
  const result = await fetch(callbackUrl);
  return result.json();
}
