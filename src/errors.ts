/**
 * Typed error classes for @parafe-trust/sdk
 * Each error maps to the broker's documented error codes.
 */

export class ParafeError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number) {
    super(message);
    this.name = 'ParafeError';
    this.code = code;
    this.statusCode = statusCode;
    // Maintain proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ValidationError extends ParafeError {
  constructor(message: string, code = 'validation_error') {
    super(message, code, 400);
    this.name = 'ValidationError';
  }
}

export class AuthError extends ParafeError {
  constructor(message: string, code = 'unauthorized') {
    super(message, code, 401);
    this.name = 'AuthError';
  }
}

export class ForbiddenError extends ParafeError {
  constructor(message: string, code = 'forbidden') {
    super(message, code, 403);
    this.name = 'ForbiddenError';
  }
}

export class NotFoundError extends ParafeError {
  constructor(message: string, code = 'not_found') {
    super(message, code, 404);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends ParafeError {
  constructor(message: string, code = 'conflict') {
    super(message, code, 409);
    this.name = 'ConflictError';
  }
}

export class ExpiredError extends ParafeError {
  constructor(message: string, code = 'expired') {
    super(message, code, 410);
    this.name = 'ExpiredError';
  }
}

export class RateLimitError extends ParafeError {
  constructor(message: string, code = 'rate_limit_exceeded') {
    super(message, code, 429);
    this.name = 'RateLimitError';
  }
}

export class InternalError extends ParafeError {
  constructor(message: string, code = 'internal_error') {
    super(message, code, 500);
    this.name = 'InternalError';
  }
}

/**
 * Map a broker HTTP response to the appropriate typed error.
 */
export function mapBrokerError(statusCode: number, body: Record<string, unknown>): ParafeError {
  const code = (body.error as string) || 'unknown_error';
  const message = (body.message as string) || (body.error as string) || 'Unknown error';

  switch (statusCode) {
    case 400:
      return new ValidationError(message, code);
    case 401:
      return new AuthError(message, code);
    case 403:
      return new ForbiddenError(message, code);
    case 404:
      return new NotFoundError(message, code);
    case 409:
      return new ConflictError(message, code);
    case 410:
      return new ExpiredError(message, code);
    case 429:
      return new RateLimitError(message, code);
    case 500:
    default:
      return new InternalError(message, code);
  }
}
