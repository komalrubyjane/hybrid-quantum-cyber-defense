import { useCallback, useEffect, useState } from "react";

import { ApiError } from "../api/client";

export type AsyncState<T> =
  | { status: "loading" }
  | { status: "error"; error: ApiError }
  | { status: "ready"; data: T };

function toApiError(error: unknown): ApiError {
  return error instanceof ApiError ? error : new ApiError("http", "Unexpected error.");
}

/**
 * Load data from the API. `key` identifies the inputs (change it to refetch for new inputs);
 * `reload()` refetches. A result is shown only for the current request token, so stale
 * responses are ignored and a new request shows the loading state.
 */
export function useAsync<T>(load: () => Promise<T>, key: string) {
  const [nonce, setNonce] = useState(0);
  const token = `${key}#${String(nonce)}`;
  const [result, setResult] = useState<{ token: string; state: AsyncState<T> } | null>(null);

  useEffect(() => {
    let active = true;
    load().then(
      (data) => {
        if (active) setResult({ token, state: { status: "ready", data } });
      },
      (error: unknown) => {
        if (active) setResult({ token, state: { status: "error", error: toApiError(error) } });
      },
    );
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `token` encodes the inputs
  }, [token]);

  const reload = useCallback(() => {
    setNonce((n) => n + 1);
  }, []);
  const state: AsyncState<T> = result?.token === token ? result.state : { status: "loading" };
  return { state, reload };
}
