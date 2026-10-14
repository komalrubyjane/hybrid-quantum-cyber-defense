import { useState } from "react";
import { Link, NavLink, Outlet, Route, Routes, useLocation } from "react-router";

import { ApiProvider } from "./api/context";
import { useApi } from "./api/useApi";
import type { Api } from "./api/endpoints";
import { Chip } from "./components/ui";
import { useAsync } from "./hooks/useAsync";
import { AssessmentDetailPage } from "./pages/AssessmentDetailPage";
import { AssessmentsPage } from "./pages/AssessmentsPage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { MitrePage } from "./pages/MitrePage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/assessments", label: "Assessments", end: false },
  { to: "/mitre", label: "MITRE ATT&CK", end: false },
  { to: "/evaluation", label: "Evaluation", end: false },
];

function ApiStatus() {
  const api = useApi();
  const { state } = useAsync(() => api.health(), "static");
  if (state.status === "loading") return <Chip tone="neutral">API: checking…</Chip>;
  if (state.status === "error") return <Chip tone="danger">API: {state.error.kind === "unavailable" ? "unreachable" : "error"}</Chip>;
  return (
    <Chip tone="accent">
      API: {state.data.status} · ATT&amp;CK {state.data.attack_version}
    </Chip>
  );
}

function BrandMark() {
  return (
    <svg className="brand__mark" viewBox="0 0 34 34" fill="none" aria-hidden="true" focusable="false">
      <circle cx="17" cy="17" r="16" stroke="#3a4240" />
      <circle cx="17" cy="17" r="10" stroke="#a5ff78" strokeOpacity="0.55" />
      <circle cx="17" cy="17" r="3.5" fill="#a5ff78" />
      <circle cx="27" cy="9" r="2" fill="#a5ff78" />
    </svg>
  );
}

function Shell() {
  const location = useLocation();
  // The mobile menu is open only for the path it was opened on, so navigating closes it.
  const [openFor, setOpenFor] = useState<string | null>(null);
  const menuOpen = openFor === location.pathname;
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="header">
        <div className="header__inner">
          <Link to="/" className="brand" aria-label="HQC Intelligence — overview">
            <BrandMark />
            <span className="brand__text">
              <span className="brand__name">HQC Intelligence</span>
              <span className="brand__sub">research prototype</span>
            </span>
          </Link>
          <button
            type="button"
            className="btn btn--ghost btn--small menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="primary-nav"
            onClick={() => {
              setOpenFor(menuOpen ? null : location.pathname);
            }}
          >
            {menuOpen ? "Close menu" : "Menu"}
          </button>
          <nav id="primary-nav" aria-label="Primary" className={`nav-wrap${menuOpen ? " is-open" : ""}`}>
            <ul className="nav">
              {NAV.map((item) => (
                <li key={item.to}>
                  <NavLink to={item.to} end={item.end} className={({ isActive }) => `nav__link${isActive ? " is-active" : ""}`}>
                    {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
          <div className="header__status" aria-label="System status">
            <ApiStatus />
            <Chip tone="approval">RECOMMENDATION-ONLY</Chip>
            <Chip tone="neutral">Risk scores are MODEL-DERIVED</Chip>
          </div>
        </div>
      </header>
      <main id="main" className="main" tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="footer">
        <div className="footer__inner">
          <p>
            Defense mode: <strong>recommendation-only</strong>. Nothing is executed from this dashboard.
          </p>
          <p>Research prototype · local use only · no authentication</p>
        </div>
      </footer>
    </div>
  );
}

export function App({ api }: { api: Api }) {
  return (
    <ApiProvider api={api}>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<OverviewPage />} />
          <Route path="assessments" element={<AssessmentsPage />} />
          <Route path="assessments/:assessmentId" element={<AssessmentDetailPage />} />
          <Route path="mitre" element={<MitrePage />} />
          <Route path="evaluation" element={<EvaluationPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </ApiProvider>
  );
}
