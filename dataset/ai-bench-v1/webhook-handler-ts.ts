import express, { Express, Request, Response } from "express";
import crypto from "crypto";
import { EventEmitter } from "events";
import fetch from "node-fetch";

// ===== MODELS =====
interface WebhookEvent {
  id: string;
  timestamp: number;
  source: string;
  payload: Record<string, any>;
  signature?: string;
  retries: number;
}

interface Webhook {
  id: string;
  callbackUrl: string;
  events: string[];
  active: boolean;
  createdAt: number;
}

interface ApiKey {
  id: string;
  key: string;
  name: string;
  lastUsed?: number;
  createdAt: number;
}

// ===== DATABASE (IN-MEMORY) =====
class Database {
  private events = new Map<string, WebhookEvent>();
  private webhooks = new Map<string, Webhook>();
  private apiKeys = new Map<string, ApiKey>();

  saveEvent(event: WebhookEvent): void {
    this.events.set(event.id, event);
  }

  getEvent(id: string): WebhookEvent | undefined {
    return this.events.get(id);
  }

  listEvents(source?: string): WebhookEvent[] {
    return Array.from(this.events.values()).filter(
      (e) => !source || e.source === source
    );
  }

  saveWebhook(webhook: Webhook): void {
    this.webhooks.set(webhook.id, webhook);
  }

  getWebhook(id: string): Webhook | undefined {
    return this.webhooks.get(id);
  }

  listWebhooks(): Webhook[] {
    return Array.from(this.webhooks.values());
  }

  deleteWebhook(id: string): boolean {
    return this.webhooks.delete(id);
  }

  saveApiKey(key: ApiKey): void {
    this.apiKeys.set(key.id, key);
  }

  getApiKeyByKey(key: string): ApiKey | undefined {
    return Array.from(this.apiKeys.values()).find((k) => k.key === key);
  }

  listApiKeys(): ApiKey[] {
    return Array.from(this.apiKeys.values());
  }

  updateApiKeyLastUsed(id: string): void {
    const key = this.apiKeys.get(id);
    if (key) key.lastUsed = Date.now();
  }

  deleteApiKey(id: string): boolean {
    return this.apiKeys.delete(id);
  }
}

// ===== API KEY MANAGER =====
class ApiKeyManager {
  constructor(private db: Database) {}

  generate(name: string): ApiKey {
    const key = `sk_${crypto.randomBytes(32).toString("hex")}`;
    const apiKey: ApiKey = {
      id: crypto.randomUUID(),
      key,
      name,
      createdAt: Date.now(),
    };
    this.db.saveApiKey(apiKey);
    return apiKey;
  }

  verify(key: string): ApiKey | null {
    const apiKey = this.db.getApiKeyByKey(key);
    if (!apiKey) return null;
    this.db.updateApiKeyLastUsed(apiKey.id);
    return apiKey;
  }

  revoke(id: string): boolean {
    return this.db.deleteApiKey(id);
  }

  list(): ApiKey[] {
    return this.db.listApiKeys();
  }
}

// ===== SIGNATURE VALIDATION =====
class SignatureValidator {
  static sign(payload: string, secret: string): string {
    return crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("hex");
  }

  static verify(payload: string, signature: string, secret: string): boolean {
    const expected = this.sign(payload, secret);
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  }
}

// ===== WEBHOOK PROCESSOR =====
class WebhookProcessor extends EventEmitter {
  private retryQueue: Map<string, NodeJS.Timeout> = new Map();

  async processEvent(
    event: WebhookEvent,
    webhooks: Webhook[]
  ): Promise<void> {
    const applicableWebhooks = webhooks.filter(
      (w) => w.active && (w.events.includes("*") || w.events.includes("*"))
    );

    for (const webhook of applicableWebhooks) {
      this.queueDelivery(event, webhook);
    }
  }

  private queueDelivery(event: WebhookEvent, webhook: Webhook): void {
    const deliveryId = `${event.id}-${webhook.id}`;
    setImmediate(() => this.deliver(event, webhook, 0, deliveryId));
  }

  private async deliver(
    event: WebhookEvent,
    webhook: Webhook,
    attempt: number,
    deliveryId: string
  ): Promise<void> {
    const maxRetries = 5;
    const backoffMs = Math.min(1000 * Math.pow(2, attempt), 32000);

    try {
      const response = await fetch(webhook.callbackUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Webhook-Id": event.id,
          "X-Webhook-Signature": event.signature || "",
          "X-Delivery-Attempt": (attempt + 1).toString(),
        },
        body: JSON.stringify(event.payload),
        timeout: 10000,
      });

      if (response.ok) {
        this.emit("delivery_success", { deliveryId, webhook, event });
        return;
      }

      throw new Error(`HTTP ${response.status}`);
    } catch (error) {
      if (attempt < maxRetries) {
        const timeout = setTimeout(() => {
          this.deliver(event, webhook, attempt + 1, deliveryId);
        }, backoffMs);
        this.retryQueue.set(deliveryId, timeout);
        this.emit("delivery_retry", { deliveryId, attempt, nextRetry: backoffMs, error });
      } else {
        this.emit("delivery_failed", { deliveryId, webhook, event, error });
      }
    }
  }

  clearRetries(deliveryId: string): void {
    const timeout = this.retryQueue.get(deliveryId);
    if (timeout) {
      clearTimeout(timeout);
      this.retryQueue.delete(deliveryId);
    }
  }
}

// ===== DEBUG UTILITIES =====
class DebugLog {
  private logs: Array<{ timestamp: number; level: string; message: string }> =
    [];
  private maxLogs = 1000;

  log(level: "INFO" | "WARN" | "ERROR", message: string): void {
    this.logs.push({ timestamp: Date.now(), level, message });
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }
    console.log(`[${level}] ${message}`);
  }

  getLogs(
    limit: number = 50,
    level?: string
  ): Array<{ timestamp: number; level: string; message: string }> {
    let filtered = this.logs;
    if (level) filtered = filtered.filter((l) => l.level === level);
    return filtered.slice(-limit);
  }

  clear(): void {
    this.logs = [];
  }
}

// ===== APP =====
class WebhookService {
  private app: Express;
  private db: Database;
  private apiKeyManager: ApiKeyManager;
  private processor: WebhookProcessor;
  private debugLog: DebugLog;
  private webhookSecret = process.env.WEBHOOK_SECRET || "dev-secret";

  constructor(port: number = 3000) {
    this.db = new Database();
    this.apiKeyManager = new ApiKeyManager(this.db);
    this.processor = new WebhookProcessor();
    this.debugLog = new DebugLog();
    this.app = express();

    this.setupMiddleware();
    this.setupRoutes();
    this.setupEventHandlers();

    this.app.listen(port, () => {
      this.debugLog.log("INFO", `Server running on port ${port}`);
    });
  }

  private setupMiddleware(): void {
    this.app.use(express.json());

    this.app.use((req: Request, res: Response, next) => {
      const apiKey = req.headers["x-api-key"] as string;
      const publicRoutes = ["/health", "/debug/logs"];

      if (publicRoutes.some((r) => req.path.startsWith(r))) {
        next();
        return;
      }

      if (!apiKey) {
        this.debugLog.log("WARN", `Missing API key for ${req.method} ${req.path}`);
        return res.status(401).json({ error: "Missing API key" });
      }

      const verified = this.apiKeyManager.verify(apiKey);
      if (!verified) {
        this.debugLog.log("WARN", `Invalid API key for ${req.method} ${req.path}`);
        return res.status(403).json({ error: "Invalid API key" });
      }

      (req as any).apiKey = verified;
      next();
    });
  }

  private setupRoutes(): void {
    // Health check
    this.app.get("/health", (req: Request, res: Response) => {
      res.json({ status: "ok", timestamp: Date.now() });
    });

    // Incoming webhook
    this.app.post("/webhooks/ingest/:source", async (req: Request, res: Response) => {
      const source = req.params.source;
      const signature = req.headers["x-signature"] as string;
      const rawBody = JSON.stringify(req.body);

      let isValid = true;
      if (signature) {
        try {
          isValid = SignatureValidator.verify(
            rawBody,
            signature,
            this.webhookSecret
          );
        } catch {
          isValid = false;
        }
      }

      const event: WebhookEvent = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        source,
        payload: req.body,
        signature: isValid ? signature : undefined,
        retries: 0,
      };

      this.db.saveEvent(event);
      this.debugLog.log("INFO", `Ingested webhook: ${event.id} from ${source}`);

      const webhooks = this.db.listWebhooks();
      await this.processor.processEvent(event, webhooks);

      res.status(202).json({ id: event.id, accepted: true });
    });

    // List events
    this.app.get("/events", (req: Request, res: Response) => {
      const source = req.query.source as string | undefined;
      const events = this.db.listEvents(source);
      res.json({ events, total: events.length });
    });

    // Get event
    this.app.get("/events/:id", (req: Request, res: Response) => {
      const event = this.db.getEvent(req.params.id);
      if (!event) return res.status(404).json({ error: "Event not found" });
      res.json(event);
    });

    // Manage webhooks
    this.app.post("/webhooks", (req: Request, res: Response) => {
      const { callbackUrl, events } = req.body;
      if (!callbackUrl || !events) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      const webhook: Webhook = {
        id: crypto.randomUUID(),
        callbackUrl,
        events: events || ["*"],
        active: true,
        createdAt: Date.now(),
      };

      this.db.saveWebhook(webhook);
      this.debugLog.log("INFO", `Created webhook: ${webhook.id}`);
      res.status(201).json(webhook);
    });

    this.app.get("/webhooks", (req: Request, res: Response) => {
      const webhooks = this.db.listWebhooks();
      res.json({ webhooks, total: webhooks.length });
    });

    this.app.get("/webhooks/:id", (req: Request, res: Response) => {
      const webhook = this.db.getWebhook(req.params.id);
      if (!webhook) return res.status(404).json({ error: "Webhook not found" });
      res.json(webhook);
    });

    this.app.patch("/webhooks/:id", (req: Request, res: Response) => {
      const webhook = this.db.getWebhook(req.params.id);
      if (!webhook) return res.status(404).json({ error: "Webhook not found" });

      if ("active" in req.body) webhook.active = req.body.active;
      if ("events" in req.body) webhook.events = req.body.events;
      if ("callbackUrl" in req.body) webhook.callbackUrl = req.body.callbackUrl;

      this.db.saveWebhook(webhook);
      this.debugLog.log("INFO", `Updated webhook: ${webhook.id}`);
      res.json(webhook);
    });

    this.app.delete("/webhooks/:id", (req: Request, res: Response) => {
      const deleted = this.db.deleteWebhook(req.params.id);
      if (!deleted) return res.status(404).json({ error: "Webhook not found" });
      this.debugLog.log("INFO", `Deleted webhook: ${req.params.id}`);
      res.status(204).send();
    });

    // API key management
    this.app.post("/api-keys", (req: Request, res: Response) => {
      const { name } = req.body;
      if (!name) return res.status(400).json({ error: "Missing name" });

      const key = this.apiKeyManager.generate(name);
      this.debugLog.log("INFO", `Generated API key: ${key.id}`);
      res.status(201).json(key);
    });

    this.app.get("/api-keys", (req: Request, res: Response) => {
      const keys = this.apiKeyManager.list().map((k) => ({
        ...k,
        key: k.key.substring(0, 10) + "...",
      }));
      res.json({ keys, total: keys.length });
    });

    this.app.delete("/api-keys/:id", (req: Request, res: Response) => {
      const revoked = this.apiKeyManager.revoke(req.params.id);
      if (!revoked) return res.status(404).json({ error: "Key not found" });
      this.debugLog.log("INFO", `Revoked API key: ${req.params.id}`);
      res.status(204).send();
    });

    // Debug endpoints
    this.app.get("/debug/logs", (req: Request, res: Response) => {
      const limit = parseInt(req.query.limit as string) || 50;
      const level = req.query.level as string | undefined;
      const logs = this.debugLog.getLogs(limit, level);
      res.json({ logs, total: logs.length });
    });

    this.app.post("/debug/logs/clear", (req: Request, res: Response) => {
      this.debugLog.clear();
      this.debugLog.log("INFO", "Debug logs cleared");
      res.json({ cleared: true });
    });

    this.app.get("/debug/status", (req: Request, res: Response) => {
      res.json({
        events: this.db.listEvents().length,
        webhooks: this.db.listWebhooks().length,
        apiKeys: this.apiKeyManager.list().length,
        uptime: process.uptime(),
      });
    });
  }

  private setupEventHandlers(): void {
    this.processor.on("delivery_success", (data) => {
      this.debugLog.log(
        "INFO",
        `Delivery success: ${data.deliveryId} to ${data.webhook.callbackUrl}`
      );
    });

    this.processor.on("delivery_retry", (data) => {
      this.debugLog.log(
        "WARN",
        `Delivery retry ${data.attempt}: ${data.deliveryId} (next in ${data.nextRetry}ms)`
      );
    });

    this.processor.on("delivery_failed", (data) => {
      this.debugLog.log(
        "ERROR",
        `Delivery failed: ${data.deliveryId} to ${data.webhook.callbackUrl}`
      );
    });
  }
}

// Start service
new WebhookService(parseInt(process.env.PORT || "3000"));