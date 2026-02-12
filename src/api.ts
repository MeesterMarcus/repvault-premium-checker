import { APIGatewayProxyResult } from "aws-lambda";

export class ApiError extends Error {
  statusCode: number;
  code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

export function makeResponse(statusCode: number, payload: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  };
}

export function makeErrorResponse(statusCode: number, code: string, message: string): APIGatewayProxyResult {
  return makeResponse(statusCode, { error: { code, message } });
}
