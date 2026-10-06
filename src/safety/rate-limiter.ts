export interface RateLimiterOptions {
  /** Sustained requests per second. Default 2. */
  readonly rps?: number;
  /** Bucket capacity (max burst). Default max(1, rps). */
  readonly burst?: number;
  /** Monotonic-ish clock in milliseconds. Injectable for tests. */
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
}

export interface RateLimiter {
  acquire(): Promise<void>;
}

const DEFAULT_RPS = 2;

export function createRateLimiter(opts: RateLimiterOptions = {}): RateLimiter {
  const rps = opts.rps ?? DEFAULT_RPS;
  if (!Number.isFinite(rps) || rps <= 0) throw new RangeError("rps must be a positive finite number");
  const capacity = Math.max(1, opts.burst ?? rps);
  const now = opts.now ?? (() => performance.now());
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const msPerToken = 1000 / rps;

  let tokens = capacity;
  let last = now();
  let queue: Promise<void> = Promise.resolve();

  const refill = (): void => {
    const t = now();
    tokens = Math.min(capacity, tokens + ((t - last) / 1000) * rps);
    last = t;
  };

  const take = async (): Promise<void> => {
    for (;;) {
      refill();
      if (tokens >= 1 - 1e-9) {
        tokens -= 1;
        return;
      }
      await sleep(Math.ceil((1 - tokens) * msPerToken));
    }
  };

  return {
    acquire(): Promise<void> {
      const run = queue.then(take);
      queue = run.catch(() => undefined);
      return run;
    },
  };
}
