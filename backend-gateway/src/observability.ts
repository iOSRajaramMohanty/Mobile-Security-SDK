import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import client from 'prom-client';

export type SecurityEvent =
  | 'unknown_key'
  | 'replay_detected'
  | 'high_risk_device'
  | 'attestation_failure'
  | 'signature_failure'
  | 'step_up_required'
  | 'step_up_verified'
  | 'step_up_failed'
  | 'step_up_token_used';

export type RequestContext = {
  requestId: string;
  startedAtMs: number;
};

declare module 'express-serve-static-core' {
  interface Request {
    _ctx?: RequestContext;
  }
}

export function requestContextMiddleware(req: Request, _res: Response, next: NextFunction): void {
  req._ctx = { requestId: randomUUID(), startedAtMs: Date.now() };
  next();
}

export function logEvent(event: SecurityEvent, details: Record<string, unknown>): void {
  // Structured JSON logs only. Never include plaintext payloads, tokens, private keys, or full public keys.
  const out = {
    ts: new Date().toISOString(),
    type: 'security_event',
    event,
    ...details,
  };
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(out));
}

export const metrics = {
  registry: new client.Registry(),
  httpRequestsTotal: new client.Counter({
    name: 'backend_gateway_http_requests_total',
    help: 'Total HTTP requests',
    labelNames: ['route', 'method', 'status'] as const,
  }),
  securityEventsTotal: new client.Counter({
    name: 'backend_gateway_security_events_total',
    help: 'Total security events',
    labelNames: ['event'] as const,
  }),
  secureRejectionsTotal: new client.Counter({
    name: 'backend_gateway_secure_rejections_total',
    help: 'Secure endpoint rejections by reason',
    labelNames: ['reason'] as const,
  }),
  riskScoreHistogram: new client.Histogram({
    name: 'backend_gateway_risk_score',
    help: 'Observed riskScore distribution on /v1/secure',
    buckets: [0, 10, 25, 50, 70, 80, 90, 100],
  }),
  stepupVerifyAttempts: new client.Counter({
    name: 'backend_gateway_stepup_verify_attempts_total',
    help: 'Total step-up verification attempts',
  }),
  stepupVerifyFailures: new client.Counter({
    name: 'backend_gateway_stepup_verify_failures_total',
    help: 'Total step-up verification failures',
    labelNames: ['reason'] as const,
  }),
};

metrics.registry.registerMetric(metrics.httpRequestsTotal);
metrics.registry.registerMetric(metrics.securityEventsTotal);
metrics.registry.registerMetric(metrics.secureRejectionsTotal);
metrics.registry.registerMetric(metrics.riskScoreHistogram);
metrics.registry.registerMetric(metrics.stepupVerifyAttempts);
metrics.registry.registerMetric(metrics.stepupVerifyFailures);
client.collectDefaultMetrics({ register: metrics.registry });

export function httpMetricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.on('finish', () => {
    const route = req.route?.path ? String(req.route.path) : req.path;
    metrics.httpRequestsTotal.labels(route, req.method, String(res.statusCode)).inc();
  });
  next();
}

export async function metricsHandler(_req: Request, res: Response): Promise<void> {
  res.setHeader('Content-Type', metrics.registry.contentType);
  res.end(await metrics.registry.metrics());
}

