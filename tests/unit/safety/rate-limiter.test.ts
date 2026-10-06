import { describe, expect, it } from "vitest";
import { createRateLimiter } from "../../../src/safety/rate-limiter.js";

function fakeTime() {
  let t = 0;
  const sleeps: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number) => {
      sleeps.push(ms);
      t += ms;
    },
    sleeps,
  };
}

describe("rate limiter", () => {
  it("allows an initial burst then spaces requests at 1/rps", async () => {
    const time = fakeTime();
    const limiter = createRateLimiter({ rps: 2, now: time.now, sleep: time.sleep });
    await limiter.acquire();
    await limiter.acquire();
    expect(time.sleeps).toEqual([]);
    await limiter.acquire();
    expect(time.sleeps).toEqual([500]);
    await limiter.acquire();
    expect(time.now()).toBe(1000);
  });

  it("defaults to 2 requests per second", async () => {
    const time = fakeTime();
    const limiter = createRateLimiter({ now: time.now, sleep: time.sleep });
    for (let i = 0; i < 6; i += 1) await limiter.acquire();
    expect(time.now()).toBe(2000);
  });

  it("refills while idle but never beyond burst capacity", async () => {
    const time = fakeTime();
    const limiter = createRateLimiter({ rps: 1, burst: 2, now: time.now, sleep: time.sleep });
    await limiter.acquire();
    await limiter.acquire();
    await time.sleep(10_000);
    time.sleeps.length = 0;
    await limiter.acquire();
    await limiter.acquire();
    expect(time.sleeps).toEqual([]);
    await limiter.acquire();
    expect(time.sleeps).toEqual([1000]);
  });

  it("serializes concurrent acquires", async () => {
    const time = fakeTime();
    const limiter = createRateLimiter({ rps: 1, burst: 1, now: time.now, sleep: time.sleep });
    await Promise.all(Array.from({ length: 4 }, () => limiter.acquire()));
    expect(time.now()).toBe(3000);
  });

  it("keeps working after a failing sleep", async () => {
    let fail = true;
    let t = 0;
    const limiter = createRateLimiter({
      rps: 1,
      now: () => t,
      sleep: async (ms) => {
        if (fail) {
          fail = false;
          throw new Error("boom");
        }
        t += ms;
      },
    });
    await limiter.acquire();
    await expect(limiter.acquire()).rejects.toThrow("boom");
    await expect(limiter.acquire()).resolves.toBeUndefined();
  });

  it("rejects invalid rates", () => {
    expect(() => createRateLimiter({ rps: 0 })).toThrow(RangeError);
    expect(() => createRateLimiter({ rps: Number.NaN })).toThrow(RangeError);
    expect(() => createRateLimiter({ rps: -1 })).toThrow(RangeError);
  });

  it("works with the real clock and sleep", async () => {
    const limiter = createRateLimiter({ rps: 100, burst: 1 });
    const start = Date.now();
    for (let i = 0; i < 4; i += 1) await limiter.acquire();
    expect(Date.now() - start).toBeGreaterThanOrEqual(25);
  });
});
