import { describe, expect, it } from "vitest";
import { classifyAddress, resolveAndPin, SsrfBlockedError } from "../../../src/safety/ssrf-guard.js";
import type { AddressClass } from "../../../src/safety/ssrf-guard.js";

describe("classifyAddress", () => {
  const table: Array<[string, AddressClass]> = [
    ["8.8.8.8", "public"],
    ["93.184.216.34", "public"],
    ["127.0.0.1", "loopback"],
    ["127.1", "loopback"],
    ["0x7f000001", "loopback"],
    ["2130706433", "loopback"],
    ["0177.0.0.1", "loopback"],
    ["[::1]", "loopback"],
    ["::1", "loopback"],
    ["10.0.0.1", "private"],
    ["172.16.5.5", "private"],
    ["172.32.0.1", "public"],
    ["192.168.1.1", "private"],
    ["100.64.0.1", "private"],
    ["100.100.100.200", "metadata"],
    ["169.254.169.254", "metadata"],
    ["169.254.1.1", "link-local"],
    ["fe80::1", "link-local"],
    ["fd00:ec2::254", "metadata"],
    ["fd12:3456::1", "private"],
    ["ff02::1", "multicast"],
    ["224.0.0.1", "multicast"],
    ["0.0.0.0", "reserved"],
    ["::", "reserved"],
    ["255.255.255.255", "reserved"],
    ["240.0.0.1", "reserved"],
    ["192.0.2.1", "reserved"],
    ["2001:db8::1", "reserved"],
    ["::ffff:169.254.169.254", "metadata"],
    ["::ffff:7f00:1", "loopback"],
    ["::ffff:10.1.2.3", "private"],
    ["::ffff:8.8.8.8", "public"],
    ["64:ff9b::a9fe:a9fe", "metadata"],
    ["2002:7f00:1::", "loopback"],
    ["2606:4700:4700::1111", "public"],
    ["fe80::1%eth0", "link-local"],
    ["::8.8.8.8", "reserved"],
    ["not-an-ip", "reserved"],
    ["", "reserved"],
    ["1.2.3.4.5", "reserved"],
    ["256.1.1.1", "reserved"],
    ["1::2::3", "reserved"],
    ["12345::1", "reserved"],
  ];
  it.each(table)("classifies %s as %s", (ip, expected) => {
    expect(classifyAddress(ip)).toBe(expected);
  });
});

const pub = async () => [{ address: "93.184.216.34", family: 4 }];

describe("resolveAndPin", () => {
  it("pins the resolved public address", async () => {
    const pinned = await resolveAndPin("example.test", { resolver: pub });
    expect(pinned).toMatchObject({ hostname: "example.test", address: "93.184.216.34", family: 4, addressClass: "public" });
  });

  it("rejects when ANY resolved address is metadata (rebinding mix)", async () => {
    const resolver = async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "169.254.169.254", family: 4 },
    ];
    await expect(resolveAndPin("evil.test", { resolver })).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it.each(["fe80::1", "ff02::1", "0.0.0.0"])("rejects %s even with allowPrivate+allowLoopback", async (address) => {
    const resolver = async () => [{ address, family: address.includes(":") ? 6 : 4 }];
    await expect(
      resolveAndPin("x.test", { resolver, allowPrivate: true, allowLoopback: true }),
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it("blocks private addresses by default and allows them with allowPrivate", async () => {
    const resolver = async () => [{ address: "10.0.0.5", family: 4 }];
    await expect(resolveAndPin("intranet.test", { resolver })).rejects.toThrow(/private/);
    const pinned = await resolveAndPin("intranet.test", { resolver, allowPrivate: true });
    expect(pinned.address).toBe("10.0.0.5");
  });

  it("blocks a public hostname that resolves to loopback unless explicitly allowed", async () => {
    const resolver = async () => [{ address: "127.0.0.1", family: 4 }];
    await expect(resolveAndPin("evil.test", { resolver })).rejects.toBeInstanceOf(SsrfBlockedError);
    await expect(resolveAndPin("evil.test", { resolver, allowLoopback: true })).resolves.toBeDefined();
  });

  it("allows loopback by default only for localhost-style targets", async () => {
    const resolver = async () => [{ address: "127.0.0.1", family: 4 }];
    await expect(resolveAndPin("localhost", { resolver })).resolves.toMatchObject({ address: "127.0.0.1" });
    await expect(resolveAndPin("app.localhost", { resolver })).resolves.toBeDefined();
    await expect(resolveAndPin("127.0.0.1")).resolves.toMatchObject({ address: "127.0.0.1" });
    await expect(resolveAndPin("localhost", { resolver, allowLoopback: false })).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it("handles IP literal hosts without invoking the resolver", async () => {
    const resolver = async (): Promise<never> => {
      throw new Error("resolver must not be called");
    };
    await expect(resolveAndPin("169.254.169.254", { resolver })).rejects.toBeInstanceOf(SsrfBlockedError);
    await expect(resolveAndPin("0x7f000001", { resolver })).resolves.toMatchObject({ address: "127.0.0.1" });
    await expect(resolveAndPin("2130706433", { resolver })).resolves.toMatchObject({ address: "127.0.0.1" });
    await expect(resolveAndPin("[::1]", { resolver })).resolves.toMatchObject({ address: "::1", family: 6 });
    await expect(resolveAndPin("[::ffff:169.254.169.254]", { resolver })).rejects.toBeInstanceOf(SsrfBlockedError);
    await expect(resolveAndPin("8.8.8.8", { resolver })).resolves.toMatchObject({ family: 4 });
  });

  it("prefers IPv4 when both families are returned", async () => {
    const resolver = async () => [
      { address: "2606:4700:4700::1111", family: 6 },
      { address: "8.8.8.8", family: 4 },
    ];
    expect((await resolveAndPin("dual.test", { resolver })).address).toBe("8.8.8.8");
  });

  it("falls back to IPv6 when it is the only family", async () => {
    const resolver = async () => [{ address: "2606:4700:4700::1111", family: 6 }];
    expect((await resolveAndPin("v6.test", { resolver })).family).toBe(6);
  });

  it("fails when resolution returns nothing, and normalizes trailing dot/case", async () => {
    await expect(resolveAndPin("nada.test", { resolver: async () => [] })).rejects.toThrow(/no addresses/);
    const seen: string[] = [];
    const resolver = async (h: string) => {
      seen.push(h);
      return [{ address: "8.8.8.8", family: 4 }];
    };
    await resolveAndPin("Example.TEST.", { resolver });
    expect(seen).toEqual(["example.test"]);
  });

  it("rejects an empty hostname", async () => {
    await expect(resolveAndPin("", { resolver: pub })).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it("uses the real resolver for localhost by default", async () => {
    const pinned = await resolveAndPin("localhost");
    expect(pinned.addressClass).toBe("loopback");
  });

  it("DNS rebinding: a later private answer is rejected, the first pin is unaffected", async () => {
    let calls = 0;
    const resolver = async () => {
      calls += 1;
      return calls === 1 ? [{ address: "93.184.216.34", family: 4 }] : [{ address: "10.0.0.1", family: 4 }];
    };
    const first = await resolveAndPin("rebind.test", { resolver });
    expect(first.address).toBe("93.184.216.34");
    await expect(resolveAndPin("rebind.test", { resolver })).rejects.toBeInstanceOf(SsrfBlockedError);
  });
});
