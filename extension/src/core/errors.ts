export class LuckError extends Error {
  public readonly code: string;
  public readonly details?: Readonly<Record<string, unknown>>;

  public constructor(code: string, message: string, details?: Readonly<Record<string, unknown>>) {
    super(message);
    this.name = 'LuckError';
    this.code = code;
    this.details = details;
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof LuckError || error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  return 'Unknown error';
}

export function assertNever(value: never): never {
  throw new LuckError('UNREACHABLE', `Unexpected value: ${String(value)}`);
}
