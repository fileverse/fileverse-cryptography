import { type Hex, isAddress } from "viem";
import { getMainnetClient } from "./client";

/**
 * Result of {@link getAddressName}.
 *
 * - `name`: the ENS name when one was found, otherwise the input `address`.
 * - `isEns`: `true` only when an ENS name was resolved.
 * - `resolved`: `true` when the lookup completed (hit or confirmed miss);
 *   `false` when the input wasn't a valid address or the lookup threw.
 *   Use this to decide whether the result is safe to cache.
 */
export interface AddressNameResult {
  name: string;
  isEns: boolean;
  resolved: boolean;
}

/**
 * Look up the primary ENS name for an Ethereum mainnet address.
 *
 * Thin wrapper over viem's `getEnsName`. Reuses a memoized mainnet
 * `PublicClient` per `providerUrl`, so it's safe to call in a hot path.
 * Errors and invalid inputs propagate — prefer {@link getAddressName} for a
 * caller-friendly result shape.
 *
 * @param address - Ethereum address (0x-prefixed hex). Not validated here.
 * @param providerUrl - Mainnet RPC endpoint that supports ENS resolution.
 * @returns The ENS name if one is set, otherwise `null`.
 */
export const resolveEnsAddress = async (
  address: string,
  providerUrl: string,
): Promise<string | null> => {
  const client = getMainnetClient(providerUrl);
  return client.getEnsName({ address: address as Hex });
};

/**
 * Resolve an address to its display name, falling back to the address itself.
 *
 * Behavior:
 * - If `address` is not a valid Ethereum address, returns `{name: address,
 *   isEns: false, resolved: false}` without making a network call.
 * - On a successful lookup with an ENS name, returns
 *   `{name: ensName, isEns: true, resolved: true}`.
 * - On a successful lookup with no ENS name, returns
 *   `{name: address, isEns: false, resolved: true}`.
 * - On a viem/network error, logs and returns `{name: address, isEns: false,
 *   resolved: false}` — `resolved: false` signals "don't cache this".
 *
 * @param address - Ethereum address to resolve.
 * @param providerUrl - Mainnet RPC endpoint. Required; throws if empty.
 * @throws If `providerUrl` is falsy.
 */
export const getAddressName = async (
  address: string,
  providerUrl: string,
): Promise<AddressNameResult> => {
  if (!providerUrl) {
    throw new Error("cannot fetch ens name without a provider url");
  }

  const response: AddressNameResult = {
    name: address,
    isEns: false,
    resolved: false,
  };

  if (!isAddress(address)) return response;

  try {
    const ensName = await resolveEnsAddress(address, providerUrl);
    if (ensName) {
      response.name = ensName;
      response.isEns = true;
      response.resolved = true;
    } else {
      response.name = address;
      response.isEns = false;
      response.resolved = true;
    }
  } catch (error) {
    console.log(error);
  }
  return response;
};