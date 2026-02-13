import test from "node:test";
import assert from "node:assert/strict";
import { APIGatewayProxyEvent } from "aws-lambda";
import { createSubscriptionWebhookHandler } from "../src/subscriptionWebhook";

function makeEvent(body: string, authorization: string): APIGatewayProxyEvent {
  return {
    body,
    headers: { authorization },
    multiValueHeaders: {},
    httpMethod: "POST",
    isBase64Encoded: false,
    path: "/subscription-webhook",
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    resource: "/subscription-webhook",
    requestContext: {} as APIGatewayProxyEvent["requestContext"],
  };
}

function parseBody(responseBody: string): any {
  return JSON.parse(responseBody);
}

test("valid signature + premium event updates profile to premium", async () => {
  process.env.WEBHOOK_PROVIDER = "revenuecat";
  process.env.WEBHOOK_SECRET = "test-secret";

  const payload = {
    event: {
      id: "evt_1",
      app_user_id: "user_1",
      type: "renewal",
      product_id: "pro_monthly",
    },
  };
  const rawBody = JSON.stringify(payload);
  const event = makeEvent(rawBody, "test-secret");

  const upsertCalls: Array<Record<string, unknown>> = [];
  const handler = createSubscriptionWebhookHandler({
    getProcessedEvent: async () => false,
    upsertUserProfile: async (input) => {
      upsertCalls.push(input as unknown as Record<string, unknown>);
    },
    recordProcessedEvent: async () => "recorded",
    nowIso: () => "2026-02-12T00:00:00.000Z",
    logInfo: () => undefined,
    logError: () => undefined,
  });

  const result = await handler(event);
  assert.equal(result.statusCode, 200);
  assert.deepEqual(parseBody(result.body), { ok: true });
  assert.equal(upsertCalls.length, 1);
  assert.equal(upsertCalls[0].isPremium, true);
});

test("valid signature + downgrade event updates profile to free", async () => {
  process.env.WEBHOOK_PROVIDER = "revenuecat";
  process.env.WEBHOOK_SECRET = "test-secret";

  const payload = {
    event: {
      id: "evt_2",
      app_user_id: "user_2",
      type: "expiration",
    },
  };
  const rawBody = JSON.stringify(payload);
  const event = makeEvent(rawBody, "test-secret");

  const upsertCalls: Array<Record<string, unknown>> = [];
  const handler = createSubscriptionWebhookHandler({
    getProcessedEvent: async () => false,
    upsertUserProfile: async (input) => {
      upsertCalls.push(input as unknown as Record<string, unknown>);
    },
    recordProcessedEvent: async () => "recorded",
    nowIso: () => "2026-02-12T00:00:00.000Z",
    logInfo: () => undefined,
    logError: () => undefined,
  });

  const result = await handler(event);
  assert.equal(result.statusCode, 200);
  assert.deepEqual(parseBody(result.body), { ok: true });
  assert.equal(upsertCalls.length, 1);
  assert.equal(upsertCalls[0].isPremium, false);
});

test("duplicate eventId returns idempotent no-op", async () => {
  process.env.WEBHOOK_PROVIDER = "revenuecat";
  process.env.WEBHOOK_SECRET = "test-secret";

  const payload = {
    event: {
      id: "evt_dup",
      app_user_id: "user_dup",
      type: "renewal",
    },
  };
  const rawBody = JSON.stringify(payload);
  const event = makeEvent(rawBody, "test-secret");

  let upsertCalled = false;
  let recordCalled = false;
  const handler = createSubscriptionWebhookHandler({
    getProcessedEvent: async () => true,
    upsertUserProfile: async () => {
      upsertCalled = true;
    },
    recordProcessedEvent: async () => {
      recordCalled = true;
      return "recorded";
    },
    nowIso: () => "2026-02-12T00:00:00.000Z",
    logInfo: () => undefined,
    logError: () => undefined,
  });

  const result = await handler(event);
  assert.equal(result.statusCode, 200);
  assert.deepEqual(parseBody(result.body), { ok: true });
  assert.equal(upsertCalled, false);
  assert.equal(recordCalled, false);
});

test("bad signature returns 401 INVALID_SIGNATURE", async () => {
  process.env.WEBHOOK_PROVIDER = "revenuecat";
  process.env.WEBHOOK_SECRET = "test-secret";

  const payload = {
    event: {
      id: "evt_3",
      app_user_id: "user_3",
      type: "renewal",
    },
  };
  const rawBody = JSON.stringify(payload);
  const event = makeEvent(rawBody, "not-valid-authorization");

  const handler = createSubscriptionWebhookHandler({
    getProcessedEvent: async () => false,
    upsertUserProfile: async () => undefined,
    recordProcessedEvent: async () => "recorded",
    nowIso: () => "2026-02-12T00:00:00.000Z",
    logInfo: () => undefined,
    logError: () => undefined,
  });

  const result = await handler(event);
  assert.equal(result.statusCode, 401);
  assert.deepEqual(parseBody(result.body), {
    error: {
      code: "INVALID_SIGNATURE",
      message: "Webhook signature verification failed.",
    },
  });
});

test("missing user ID returns 400 MISSING_USER_ID", async () => {
  process.env.WEBHOOK_PROVIDER = "revenuecat";
  process.env.WEBHOOK_SECRET = "test-secret";

  const payload = {
    event: {
      id: "evt_4",
      type: "renewal",
    },
  };
  const rawBody = JSON.stringify(payload);
  const event = makeEvent(rawBody, "test-secret");

  const handler = createSubscriptionWebhookHandler({
    getProcessedEvent: async () => false,
    upsertUserProfile: async () => undefined,
    recordProcessedEvent: async () => "recorded",
    nowIso: () => "2026-02-12T00:00:00.000Z",
    logInfo: () => undefined,
    logError: () => undefined,
  });

  const result = await handler(event);
  assert.equal(result.statusCode, 400);
  assert.deepEqual(parseBody(result.body), {
    error: {
      code: "MISSING_USER_ID",
      message: "Webhook event did not include a userId.",
    },
  });
});

test("RevenueCat TEST event returns 200 no-op", async () => {
  process.env.WEBHOOK_PROVIDER = "revenuecat";
  process.env.WEBHOOK_SECRET = "test-secret";

  const payload = {
    event: {
      type: "TEST",
    },
  };
  const rawBody = JSON.stringify(payload);
  const event = makeEvent(rawBody, "test-secret");

  const handler = createSubscriptionWebhookHandler({
    getProcessedEvent: async () => false,
    upsertUserProfile: async () => undefined,
    recordProcessedEvent: async () => "recorded",
    nowIso: () => "2026-02-12T00:00:00.000Z",
    logInfo: () => undefined,
    logError: () => undefined,
  });

  const result = await handler(event);
  assert.equal(result.statusCode, 200);
  assert.deepEqual(parseBody(result.body), { ok: true });
});
