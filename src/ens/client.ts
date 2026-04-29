import { createPublicClient, http, type PublicClient } from "viem";
import { mainnet } from "viem/chains";

const clientsByUrl = new Map<string, PublicClient>();

/**
 * Get a memoized viem mainnet `PublicClient` for the given RPC URL.
 *
 * One client is created per distinct URL and cached for the lifetime of the
 * module, so repeated callers share connection pooling and avoid the cost of
 * re-instantiating a client on every lookup.
 *
 * @param url - Mainnet RPC endpoint URL.
 */
export const getMainnetClient = (url: string): PublicClient => {
  const existing = clientsByUrl.get(url);
  if (existing) return existing;

  const client = createPublicClient({
    transport: http(url),
    chain: mainnet,
  });
  clientsByUrl.set(url, client);
  return client;
};

/** @internal Test-only: clear the memoized client map between cases. */
export const __resetMainnetClientsForTest = () => {
  clientsByUrl.clear();
};