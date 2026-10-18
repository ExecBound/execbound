// SPDX-License-Identifier: AGPL-3.0-only
import { createContext, useContext, type ReactNode, type TableHTMLAttributes, type TdHTMLAttributes, type ThHTMLAttributes } from "react";

export type Density = "comfortable" | "compact";

const DensityContext = createContext<Density>("comfortable");

/** A captioned table with a sticky header, scoped column headers and a density setting. */
export function Table({
  caption,
  density = "comfortable",
  children,
  className,
  ...rest
}: TableHTMLAttributes<HTMLTableElement> & {
  caption: string;
  density?: Density;
  children: ReactNode;
}) {
  return (
    <DensityContext.Provider value={density}>
      {/* The wrapper scrolls sideways when the table is wider than its card, so it is a
          region the keyboard can reach, named by the caption (axe: scrollable-region-focusable). */}
      <div className="table-wrap" tabIndex={0} role="region" aria-label={caption}>
        <table
          className={["table", `table-${density}`, className].filter(Boolean).join(" ")}
          {...rest}
        >
          <caption className="sr-only">{caption}</caption>
          {children}
        </table>
      </div>
    </DensityContext.Provider>
  );
}

export function Th({ children, ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th scope="col" {...rest}>
      {children}
    </th>
  );
}

export function Td({ mono = false, className, ...rest }: TdHTMLAttributes<HTMLTableCellElement> & { mono?: boolean }) {
  const classes = [mono ? "mono" : undefined, className].filter(Boolean).join(" ");
  return <td className={classes === "" ? undefined : classes} {...rest} />;
}

export function useDensity(): Density {
  return useContext(DensityContext);
}
