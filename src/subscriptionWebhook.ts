import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { createHmac, timingSafeEqual } from "crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { ApiError, makeErrorResponse, makeResponse } from "./api";
import { getWebhookConfig, WebhookConfig, WebhookProvider } from "./config";

interface NormalizedWebhookEvent {
  eventId: string;
  userId: string;
  isPremium: boolean;
  plan?: string;
  expiresAt?: string;
}

interface UpsertProfileInput {
  userId: string;
  isPremium: boolean;
  plan?: string;
  expiresAt?: string;
  updatedAt: string;
  source: string;
}

interface RecordProcessedEventInput {
  eventId: string;
  provider: string;
  userId: string;
  processedAt: string;
}

interface HandlerDependencies {
  getProcessedEvent: (eventId: string) => Promise<boolean>;
  upsertUserProfile: (input: UpsertProfileInput) => Promise<void>;
  recordProcessedEvent: (input: RecordProcessedEventInput) => Promise<"recorded" | "duplicate">;
  nowIso: () => string;
  logInfo: (payload: Record<string, unknown>) => void;
  logError: (payload: Record<string, unknown>) => void;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getHeaderValue(headers: Record<string, string | undefined> | null | undefined, name: string): string | undefined {
  if (!headers) {
    return undefined;
  }
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target && typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

function safeTimingEqualHex(actualHex: string, expectedHex: string): boolean {
  if (actualHex.length !== expectedHex.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(actualHex, "hex"), Buffer.from(expectedHex, "hex"));
}

function safeTimingEqualString(actual: string, expected: string): boolean {
  if (actual.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(actual, "utf8"), Buffer.from(expected, "utf8"));
}

function verifyRevenueCatAuthorization(
  headers: Record<string, string | undefined> | null | undefined,
  secret: string
): boolean {
  const authorization = getHeaderValue(headers, "authorization");
  if (!authorization || !secret) {
    return false;
  }
  return safeTimingEqualString(authorization, secret);
}

function verifyStripeSignature(
  headers: Record<string, string | undefined> | null | undefined,
  rawBody: string,
  secret: string
): boolean {
  const signature = getHeaderValue(headers, "stripe-signature");
  if (!signature || !secret) {
    return false;
  }

  let timestamp = "";
  const v1Values: string[] = [];
  for (const part of signature.split(",")) {
    const [key, value] = part.split("=", 2);
    if (key === "t" && value) {
      timestamp = value;
    } else if (key === "v1" && value) {
      v1Values.push(value);
    }
  }

  if (!timestamp || v1Values.length === 0) {
    return false;
  }

  const signedPayload = `${timestamp}.${rawBody}`;
  const expected = createHmac("sha256", secret).update(signedPayload).digest("hex");
  return v1Values.some((v1) => safeTimingEqualHex(v1.toLowerCase(), expected.toLowerCase()));
}

function verifySignature(
  provider: WebhookProvider,
  headers: Record<string, string | undefined> | null | undefined,
  rawBody: string,
  secret: string
): boolean {
  if (provider === "stripe") {
    return verifyStripeSignature(headers, rawBody, secret);
  }
  return verifyRevenueCatAuthorization(headers, secret);
}

function normalizeRevenueCatEvent(payload: unknown): NormalizedWebhookEvent {
  if (!isRecord(payload)) {
    throw new ApiError(400, "INVALID_EVENT", "Webhook payload must be a JSON object.");
  }

  const rawEvent = isRecord(payload.event) ? payload.event : payload;
  const eventId = typeof rawEvent.id === "string" ? rawEvent.id : typeof rawEvent.event_id === "string" ? rawEvent.event_id : "";
  const transferredTo = Array.isArray(rawEvent.transferred_to) ? rawEvent.transferred_to : undefined;
  const transferUserId = transferredTo && typeof transferredTo[0] === "string" ? transferredTo[0] : "";
  const userId =
    typeof rawEvent.app_user_id === "string"
      ? rawEvent.app_user_id
      : typeof rawEvent.user_id === "string"
        ? rawEvent.user_id
        : transferUserId;

  if (!eventId) {
    throw new ApiError(400, "INVALID_EVENT", "Missing eventId.");
  }
  if (!userId) {
    throw new ApiError(400, "MISSING_USER_ID", "Webhook event did not include a userId.");
  }

  const eventTypeRaw =
    typeof rawEvent.type === "string"
      ? rawEvent.type
      : typeof rawEvent.event_type === "string"
        ? rawEvent.event_type
        : "";
  const eventType = eventTypeRaw.trim().toLowerCase();

  const premiumEventTypes = new Set([
    "initial_purchase",
    "renewal",
    "uncancellation",
    "billing_recovery",
    "trial_started",
    "trial_converted",
    "active",
    "trialing",
    "renewed",
    "purchase",
    "product_change",
    "subscription_resumed",
    "transfer",
  ]);
  const freeEventTypes = new Set([
    "expiration",
    "cancellation",
    "refund",
    "billing_issue",
    "billing_problem",
    "expired",
    "canceled",
    "refunded",
    "grace_period_expired",
    "subscription_paused",
  ]);

  let isPremium: boolean;
  if (premiumEventTypes.has(eventType)) {
    isPremium = true;
  } else if (freeEventTypes.has(eventType)) {
    isPremium = false;
  } else {
    throw new ApiError(400, "INVALID_EVENT", `Unhandled RevenueCat event type: ${eventTypeRaw || "unknown"}.`);
  }

  const plan =
    typeof rawEvent.product_id === "string"
      ? rawEvent.product_id
      : typeof rawEvent.entitlement_id === "string"
        ? rawEvent.entitlement_id
        : undefined;
  const expiresAt =
    typeof rawEvent.expiration_at_ms === "number"
      ? new Date(rawEvent.expiration_at_ms).toISOString()
      : typeof rawEvent.expires_date === "string"
        ? rawEvent.expires_date
        : undefined;

  return { eventId, userId, isPremium, plan, expiresAt };
}

function normalizeStripeEvent(payload: unknown): NormalizedWebhookEvent {
  if (!isRecord(payload)) {
    throw new ApiError(400, "INVALID_EVENT", "Webhook payload must be a JSON object.");
  }
  const eventId = typeof payload.id === "string" ? payload.id : "";
  if (!eventId) {
    throw new ApiError(400, "INVALID_EVENT", "Missing eventId.");
  }

  const data = isRecord(payload.data) ? payload.data : {};
  const eventObject = isRecord(data.object) ? data.object : {};
  const metadata = isRecord(eventObject.metadata) ? eventObject.metadata : {};
  const userId =
    typeof metadata.userId === "string"
      ? metadata.userId
      : typeof metadata.user_id === "string"
        ? metadata.user_id
        : "";
  if (!userId) {
    throw new ApiError(400, "MISSING_USER_ID", "Webhook event did not include a userId.");
  }

  const eventType = typeof payload.type === "string" ? payload.type : "";
  const premiumEventTypes = new Set([
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "invoice.paid",
  ]);
  const freeEventTypes = new Set([
    "customer.subscription.deleted",
    "invoice.payment_failed",
    "charge.refunded",
  ]);

  let isPremium: boolean;
  if (premiumEventTypes.has(eventType)) {
    isPremium = true;
  } else if (freeEventTypes.has(eventType)) {
    isPremium = false;
  } else {
    throw new ApiError(400, "INVALID_EVENT", `Unhandled Stripe event type: ${eventType || "unknown"}.`);
  }

  const plan =
    typeof eventObject.price === "string"
      ? eventObject.price
      : typeof eventObject.plan === "string"
        ? eventObject.plan
        : undefined;
  const expiresAt =
    typeof eventObject.current_period_end === "number"
      ? new Date(eventObject.current_period_end * 1000).toISOString()
      : undefined;

  return { eventId, userId, isPremium, plan, expiresAt };
}

function normalizeEvent(provider: WebhookProvider, payload: unknown): NormalizedWebhookEvent {
  if (provider === "stripe") {
    return normalizeStripeEvent(payload);
  }
  return normalizeRevenueCatEvent(payload);
}

function isRevenueCatTestEvent(payload: unknown): boolean {
  if (!isRecord(payload)) {
    return false;
  }
  const rawEvent = isRecord(payload.event) ? payload.event : payload;
  const eventTypeRaw =
    typeof rawEvent.type === "string"
      ? rawEvent.type
      : typeof rawEvent.event_type === "string"
        ? rawEvent.event_type
        : "";
  return eventTypeRaw.trim().toLowerCase() === "test";
}

function getRawBody(event: APIGatewayProxyEvent): string {
  if (!event.body) {
    return "";
  }
  if (event.isBase64Encoded) {
    return Buffer.from(event.body, "base64").toString("utf-8");
  }
  return event.body;
}

function buildDynamoDependencies(config: WebhookConfig): HandlerDependencies {
  const ddbClient = new DynamoDBClient({ region: process.env.AWS_REGION || "us-east-1" });
  const ddbDocClient = DynamoDBDocumentClient.from(ddbClient);

  return {
    getProcessedEvent: async (eventId: string): Promise<boolean> => {
      const { Item } = await ddbDocClient.send(
        new GetCommand({
          TableName: config.webhookEventsTableName,
          Key: { eventId },
        })
      );
      return !!Item;
    },
    upsertUserProfile: async (input: UpsertProfileInput): Promise<void> => {
      const setClauses = [
        "isPremium = :isPremium",
        "subscriptionTier = :subscriptionTier",
        "updatedAt = :updatedAt",
        "#src = :source",
      ];
      const removeClauses: string[] = [];
      const expressionAttributeValues: Record<string, unknown> = {
        ":isPremium": input.isPremium,
        ":subscriptionTier": input.isPremium ? "premium" : "free",
        ":updatedAt": input.updatedAt,
        ":source": input.source,
      };
      const expressionAttributeNames: Record<string, string> = { "#src": "source" };

      if (input.plan !== undefined) {
        setClauses.push("plan = :plan");
        expressionAttributeValues[":plan"] = input.plan;
      } else {
        removeClauses.push("plan");
      }

      if (input.expiresAt !== undefined) {
        setClauses.push("expiresAt = :expiresAt");
        expressionAttributeValues[":expiresAt"] = input.expiresAt;
      } else {
        removeClauses.push("expiresAt");
      }

      const updateExpression = removeClauses.length
        ? `SET ${setClauses.join(", ")} REMOVE ${removeClauses.join(", ")}`
        : `SET ${setClauses.join(", ")}`;

      await ddbDocClient.send(
        new UpdateCommand({
          TableName: config.userProfileTableName,
          Key: { userId: input.userId },
          UpdateExpression: updateExpression,
          ExpressionAttributeNames: expressionAttributeNames,
          ExpressionAttributeValues: expressionAttributeValues,
        })
      );
    },
    recordProcessedEvent: async (input: RecordProcessedEventInput): Promise<"recorded" | "duplicate"> => {
      try {
        await ddbDocClient.send(
          new PutCommand({
            TableName: config.webhookEventsTableName,
            Item: input,
            ConditionExpression: "attribute_not_exists(eventId)",
          })
        );
        return "recorded";
      } catch (error: unknown) {
        if (isRecord(error) && error.name === "ConditionalCheckFailedException") {
          return "duplicate";
        }
        throw error;
      }
    },
    nowIso: () => new Date().toISOString(),
    logInfo: (payload: Record<string, unknown>) => console.log(JSON.stringify(payload)),
    logError: (payload: Record<string, unknown>) => console.error(JSON.stringify(payload)),
  };
}

export function createSubscriptionWebhookHandler(overrides?: Partial<HandlerDependencies>) {
  return async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const config = getWebhookConfig();
    const deps = { ...buildDynamoDependencies(config), ...overrides };

    let eventIdForLog = "unknown";
    let userIdForLog = "unknown";
    let tierForLog = "unknown";
    let stageForLog = "start";
    const provider = config.webhookProvider;

    try {
      const rawBody = getRawBody(event);
      stageForLog = "verify_signature";
      const isValidSignature = verifySignature(provider, event.headers, rawBody, config.webhookSecret);
      if (!isValidSignature) {
        throw new ApiError(401, "INVALID_SIGNATURE", "Webhook signature verification failed.");
      }

      let payload: unknown;
      try {
        stageForLog = "parse_json";
        payload = JSON.parse(rawBody);
      } catch {
        throw new ApiError(400, "INVALID_JSON", "Request body must be valid JSON.");
      }

      if (provider === "revenuecat" && isRevenueCatTestEvent(payload)) {
        deps.logInfo({
          eventId: "test_event",
          provider,
          userId: "n/a",
          tier: "n/a",
          status: "test_noop",
        });
        return makeResponse(200, { ok: true });
      }

      stageForLog = "normalize_event";
      const normalized = normalizeEvent(provider, payload);
      eventIdForLog = normalized.eventId;
      userIdForLog = normalized.userId;
      tierForLog = normalized.isPremium ? "premium" : "free";

      stageForLog = "idempotency_check";
      const alreadyProcessed = await deps.getProcessedEvent(normalized.eventId);
      if (alreadyProcessed) {
        deps.logInfo({
          eventId: normalized.eventId,
          provider,
          userId: normalized.userId,
          tier: tierForLog,
          status: "duplicate_noop",
        });
        return makeResponse(200, { ok: true });
      }

      const updatedAt = deps.nowIso();
      stageForLog = "upsert_profile";
      await deps.upsertUserProfile({
        userId: normalized.userId,
        isPremium: normalized.isPremium,
        plan: normalized.plan,
        expiresAt: normalized.expiresAt,
        updatedAt,
        source: `${provider}_webhook`,
      });

      stageForLog = "record_event";
      const result = await deps.recordProcessedEvent({
        eventId: normalized.eventId,
        provider,
        userId: normalized.userId,
        processedAt: updatedAt,
      });

      deps.logInfo({
        eventId: normalized.eventId,
        provider,
        userId: normalized.userId,
        tier: tierForLog,
        status: result === "duplicate" ? "race_duplicate_noop" : "updated",
      });

      return makeResponse(200, { ok: true });
    } catch (error: unknown) {
      if (error instanceof ApiError) {
        deps.logError({
          eventId: eventIdForLog,
          provider,
          userId: userIdForLog,
          tier: tierForLog,
          status: "error",
          stage: stageForLog,
        });
        return makeErrorResponse(error.statusCode, error.code, error.message);
      }

      const unknownError = isRecord(error) ? error : {};
      deps.logError({
        eventId: eventIdForLog,
        provider,
        userId: userIdForLog,
        tier: tierForLog,
        status: "error",
        stage: stageForLog,
        errorName: typeof unknownError.name === "string" ? unknownError.name : "UnknownError",
        errorMessage: typeof unknownError.message === "string" ? unknownError.message : "Unknown error",
      });
      return makeErrorResponse(500, "INTERNAL_ERROR", "An unexpected internal error occurred.");
    }
  };
}

export const handler = createSubscriptionWebhookHandler();
