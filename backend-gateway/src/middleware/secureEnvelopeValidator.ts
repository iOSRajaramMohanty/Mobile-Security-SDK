import type { NextFunction, Request, Response } from 'express';
import type { EnvelopeInput } from '../secureEnvelope.js';
import { parseEnvelopeInput } from '../parseEnvelopeInput.js';

export type RequestWithEnvelope = Request & { validatedEnvelope: EnvelopeInput };

export function secureEnvelopeValidator(req: Request, res: Response, next: NextFunction): void {
  const parsed = parseEnvelopeInput(req.body);
  if (!parsed.ok) {
    res.status(400).json({ ok: false, reason: parsed.reason });
    return;
  }
  (req as RequestWithEnvelope).validatedEnvelope = parsed.envelope;
  next();
}
