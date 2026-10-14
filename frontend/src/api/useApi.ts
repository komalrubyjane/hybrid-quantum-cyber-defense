import { useContext } from "react";

import { ApiContext } from "./apiContext";
import type { Api } from "./endpoints";

export function useApi(): Api {
  const api = useContext(ApiContext);
  if (api === null) throw new Error("useApi must be used inside <ApiProvider>");
  return api;
}
