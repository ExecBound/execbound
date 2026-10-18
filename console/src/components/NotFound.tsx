// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";
import { useLayoutEffect } from "react";

import { removeFrame } from "../lib/frame";
import { titleNoun, usePageName, type PageName } from "../shell/page-name";
import { Card } from "./ui/Card";

const NOT_FOUND: PageName = { crumbs: [], current: "Not found", title: [titleNoun("Not found")] };

export function NotFound() {
  usePageName(NOT_FOUND);
  useLayoutEffect(removeFrame, []);
  return (
    <Card>
      <h1 tabIndex={-1}>There is no page here</h1>
      <p className="lead">The address does not name a console page.</p>
      <Link to="/" className="btn">
        Go home
      </Link>
    </Card>
  );
}
