import { Link } from "react-router";

import { PageHero } from "../components/ui";

export function NotFoundPage() {
  return (
    <div className="page">
      <PageHero
        eyebrow="404"
        title="Page not found"
        lead={
          <>
            This dashboard page does not exist. <Link to="/">Return to the overview</Link>.
          </>
        }
      />
    </div>
  );
}
