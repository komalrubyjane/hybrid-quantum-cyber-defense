import { createContext } from "react";

import type { Api } from "./endpoints";

export const ApiContext = createContext<Api | null>(null);
