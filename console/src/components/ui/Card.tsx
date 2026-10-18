// SPDX-License-Identifier: AGPL-3.0-only
import type { HTMLAttributes, ReactNode } from "react";

export function Card({
  title,
  aside,
  children,
  className,
  ...rest
}: HTMLAttributes<HTMLElement> & { title?: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className={className === undefined ? "card" : `card ${className}`} {...rest}>
      {title !== undefined ? (
        <header className="card-head">
          <h2 className="card-title">{title}</h2>
          {aside !== undefined ? <div className="card-aside">{aside}</div> : null}
        </header>
      ) : null}
      <div className="card-body">{children}</div>
    </section>
  );
}
