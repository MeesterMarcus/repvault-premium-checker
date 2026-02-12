export type WebhookProvider = "revenuecat" | "stripe";

export interface WebhookConfig {
  userProfileTableName: string;
  webhookEventsTableName: string;
  webhookProvider: WebhookProvider;
  webhookSecret: string;
  logLevel: string;
}

export function getWebhookConfig(): WebhookConfig {
  const providerRaw = (process.env.WEBHOOK_PROVIDER || "revenuecat").trim().toLowerCase();
  const webhookProvider = providerRaw === "stripe" ? "stripe" : "revenuecat";

  return {
    userProfileTableName: process.env.USER_PROFILE_TABLE_NAME || "UserProfileTable",
    webhookEventsTableName: process.env.WEBHOOK_EVENTS_TABLE_NAME || "WebhookEventsTable",
    webhookProvider,
    webhookSecret: process.env.WEBHOOK_SECRET || "",
    logLevel: process.env.LOG_LEVEL || "info",
  };
}
