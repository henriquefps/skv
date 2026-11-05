/** Errors shown to the user as `skv: <message>`. `usage` exits 2, everything else exits 1. */
export class SkvError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SkvError';
    this.code = code;
  }

  get exitCode() {
    return this.code === 'usage' ? 2 : 1;
  }
}

export const usage = (message) => new SkvError('usage', message);
