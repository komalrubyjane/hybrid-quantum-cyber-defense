import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";

import { App } from "./App";
import { ApiClient } from "./api/client";
import { createApi } from "./api/endpoints";
import "./styles/theme.css";

const root = document.getElementById("root");
if (root === null) throw new Error("Missing #root element");

// Only the base URL is configurable (VITE_API_BASE_URL); no secrets live in the frontend.
const api = createApi(new ApiClient(import.meta.env.VITE_API_BASE_URL ?? ""));

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <App api={api} />
    </BrowserRouter>
  </StrictMode>,
);
