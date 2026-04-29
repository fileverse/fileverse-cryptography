import { describe, it, expect, vi, beforeEach } from "vitest";

const getEnsName = vi.fn();
const createPublicClient = vi.fn(() => ({ getEnsName }));
const http = vi.fn((url?: string) => ({ __transport: "http", url }));

vi.mock("viem", async () => {
  const actual = await vi.importActual<typeof import("viem")>("viem");
  return {
    ...actual,
    createPublicClient: (...args: unknown[]) => createPublicClient(...args as []),
    http: (...args: unknown[]) => http(...(args as [string?])),
  };
});

import { getAddressName, resolveEnsAddress } from "../index";
import { __resetMainnetClientsForTest } from "../client";

const VALID_ADDRESS = "0x1234567890123456789012345678901234567890";
const PROVIDER_URL = "https://eth.example/rpc";

beforeEach(() => {
  vi.clearAllMocks();
  __resetMainnetClientsForTest();
});

describe("ens/getAddressName", () => {
  it("returns ENS name when resolver hits", async () => {
    getEnsName.mockResolvedValueOnce("vitalik.eth");

    const result = await getAddressName(VALID_ADDRESS, PROVIDER_URL);

    expect(result).toEqual({
      name: "vitalik.eth",
      isEns: true,
      resolved: true,
    });
    expect(getEnsName).toHaveBeenCalledWith({ address: VALID_ADDRESS });
  });

  it("returns address with resolved=true when no ENS exists", async () => {
    getEnsName.mockResolvedValueOnce(null);

    const result = await getAddressName(VALID_ADDRESS, PROVIDER_URL);

    expect(result).toEqual({
      name: VALID_ADDRESS,
      isEns: false,
      resolved: true,
    });
  });

  it("short-circuits non-address inputs without calling viem", async () => {
    const result = await getAddressName("not-an-address", PROVIDER_URL);

    expect(result).toEqual({
      name: "not-an-address",
      isEns: false,
      resolved: false,
    });
    expect(createPublicClient).not.toHaveBeenCalled();
    expect(getEnsName).not.toHaveBeenCalled();
  });

  it("throws when providerUrl is missing", async () => {
    await expect(getAddressName(VALID_ADDRESS, "")).rejects.toThrow(
      /provider url/i,
    );
  });

  it("returns unresolved default and swallows viem errors", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    getEnsName.mockRejectedValueOnce(new Error("network down"));

    const result = await getAddressName(VALID_ADDRESS, PROVIDER_URL);

    expect(result).toEqual({
      name: VALID_ADDRESS,
      isEns: false,
      resolved: false,
    });
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});

describe("ens client memoization", () => {
  it("reuses the client for the same providerUrl", async () => {
    getEnsName.mockResolvedValue(null);

    await resolveEnsAddress(VALID_ADDRESS, PROVIDER_URL);
    await resolveEnsAddress(VALID_ADDRESS, PROVIDER_URL);

    expect(createPublicClient).toHaveBeenCalledTimes(1);
  });

  it("creates separate clients for distinct URLs", async () => {
    getEnsName.mockResolvedValue(null);

    await resolveEnsAddress(VALID_ADDRESS, PROVIDER_URL);
    await resolveEnsAddress(VALID_ADDRESS, "https://other.example/rpc");

    expect(createPublicClient).toHaveBeenCalledTimes(2);
  });
});