// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { clock, CountdownRing, Meter, Sparkline, StackedBars, summariseLine } from "./index";

describe("the charts", () => {
  it("draw stacked bars only with token colours and describe them as a summary", () => {
    const { container } = render(
      <StackedBars
        title="Decisions by day"
        labels={["Sat", "Sun"]}
        series={[
          { label: "allowed", tone: "allow", values: [8, 3] },
          { label: "denied", tone: "deny", values: [1, 0] },
        ]}
      />,
    );
    const rects = container.querySelectorAll("rect");
    expect(rects).toHaveLength(4);
    for (const rect of rects) expect(rect.getAttribute("fill")).toMatch(/^var\(--eb-(allow|deny)\)$/);
    expect(screen.getByRole("figure", { name: "Decisions by day" })).toHaveTextContent(
      "12 in all: allowed 11, denied 1. 2 of 2 columns carry something",
    );
    const heights = [...rects].map((rect) => Number(rect.getAttribute("height")));
    expect(Math.max(...heights)).toBeCloseTo(138 * (8 / 9), 5);
  });

  it("summarise a mostly empty chart by where the activity is, never column by column", () => {
    const values = Array.from({ length: 28 }, (_, index) => (index === 9 ? 21 : 0));
    render(
      <StackedBars
        title="Decisions by outcome over the last 7 days"
        labels={Array.from({ length: 28 }, (_, index) => (index % 4 === 0 ? `day ${String(index / 4)}` : ""))}
        columns={Array.from({ length: 28 }, (_, index) => `col ${String(index)}`)}
        span="7 days"
        step="6 hours"
        series={[
          { label: "Allowed", tone: "allow", values },
          { label: "Stale", tone: "stale", values: Array.from({ length: 28 }, () => 0) },
        ]}
      />,
    );
    const caption = screen.getByRole("figure", { name: /Decisions by outcome/ });
    expect(caption).toHaveTextContent(
      "21 in all over the last 7 days, one column every 6 hours: Allowed 21, Stale 0.",
    );
    expect(caption).toHaveTextContent("All of it is in one of 28 columns, col 9.");
    // The enumeration #427 asked us to drop: no run of empty columns is read out.
    expect(caption).not.toHaveTextContent("col 0: Allowed 0");
  });

  it("keeps the first and last column labels inside the plot", () => {
    // The Home chart's shape: 28 six-hour columns, a label where a day starts. A label that
    // would cross an edge is anchored to it, so its position never rests on an estimate of its
    // width; "16 Wed" measured wider than that estimate on the Linux runner and lost a
    // sixteenth of a unit off its first character. A label that fits stays under its column.
    const labels = Array.from({ length: 28 }, (_, index) =>
      index === 0 ? "16 Wed" : index === 12 ? "19 Sat" : index === 27 ? "22 Tue" : "",
    );
    const { container } = render(
      <StackedBars
        title="Decisions by outcome"
        labels={labels}
        series={[{ label: "allowed", tone: "allow", values: labels.map(() => 1) }]}
      />,
    );
    const drawn = [...container.querySelectorAll("text")].filter((node) => node.textContent !== "");
    const placed = drawn.map((node) => [node.getAttribute("text-anchor"), Number(node.getAttribute("x"))]);
    const bar = (640 - 6 * 27) / 28;
    expect(placed[0]).toEqual(["start", 1]);
    expect(placed[1]).toEqual(["middle", expect.closeTo(12 * (bar + 6) + bar / 2, 5)]);
    expect(placed[2]).toEqual(["end", 639]);
  });

  it("draw a sparkline and summarise what the line holds, never \"from 0 to 0\"", () => {
    const { container } = render(<Sparkline title="Decisions this week" values={[3, 9, 4]} />);
    expect(container.querySelector("polyline")?.getAttribute("stroke")).toBe("var(--eb-accent)");
    expect(screen.getByRole("figure")).toHaveTextContent(
      "Decisions this week. 16 in all across 3 periods, every one of them carrying something, the tallest 9. It ends at 4.",
    );
  });

  it("describe a sparkline over a mostly empty week by where its mass is", () => {
    // The Decisions tile of the live pilot: 28 six-hour periods, three of them carrying
    // anything, which the old caption read out as "from 0 to 0, low 0, high 32" (#427).
    const week = Array.from({ length: 28 }, (_, index) => (index === 6 ? 32 : index === 9 || index === 20 ? 7 : 0));
    expect(summariseLine("Decisions per 6 hours over the last 7 days", week)).toBe(
      "Decisions per 6 hours over the last 7 days. 46 in all, 3 of 28 periods carrying something, the tallest 32. It ends at 0.",
    );
    expect(summariseLine("Decisions", Array.from({ length: 28 }, () => 0))).toBe("Decisions. Nothing.");
    expect(summariseLine("Decisions", [])).toBe("Decisions. Nothing.");
    expect(summariseLine("Decisions", Array.from({ length: 4 }, (_, index) => (index === 3 ? 5 : 0)))).toBe(
      "Decisions. 5 in all, all of it in one of 4 periods. It ends at 5.",
    );
    expect(summariseLine("Decisions", [2])).toBe(
      "Decisions. 2 in all across 1 period, every one of them carrying something, the tallest 2. It ends at 2.",
    );
  });

  it("make a meter a meter, with the fraction as its width", () => {
    const { container } = render(<Meter label="Isolations this hour" value={9} max={12} />);
    const meter = screen.getByRole("meter", { name: "Isolations this hour" });
    expect(meter).toHaveAttribute("aria-valuenow", "9");
    expect(meter).toHaveAttribute("aria-valuetext", "9 of 12");
    expect(container.querySelector<HTMLElement>(".meter-fill")?.style.width).toBe("75%");
    expect(container.querySelector<HTMLElement>(".meter-fill")?.style.background).toContain("--eb-hold");
  });

  it("draw the countdown ring from the time left and name it", () => {
    const { container } = render(<CountdownRing remainingSeconds={522} totalSeconds={900} />);
    expect(screen.getByRole("img", { name: "8:42 left" })).toBeInTheDocument();
    const arc = container.querySelectorAll("circle")[1];
    expect(arc?.getAttribute("stroke")).toBe("var(--eb-hold)");
    render(<CountdownRing remainingSeconds={125} totalSeconds={900} size={72} />);
    expect(screen.getByRole("img", { name: "2:05 left" })).toBeInTheDocument();
    expect(clock(0)).toBe("0:00");
    expect(clock(3599)).toBe("59:59");
  });

  it("draw the ring's arc as the fraction left, turning to the deny colour at a quarter", () => {
    // A 30 px ring with a 3 px stroke has a radius of 13.5, so its full arc is 27 pi.
    const circumference = 2 * Math.PI * 13.5;
    const arcOf = (remainingSeconds: number) => {
      const { container, unmount } = render(<CountdownRing remainingSeconds={remainingSeconds} totalSeconds={900} />);
      const [track, arc] = [...container.querySelectorAll("circle")];
      const drawn = {
        track: track?.getAttribute("stroke"),
        stroke: arc?.getAttribute("stroke"),
        dasharray: Number(arc?.getAttribute("stroke-dasharray")),
        offset: Number(arc?.getAttribute("stroke-dashoffset")),
      };
      unmount();
      return drawn;
    };
    const third = arcOf(300);
    expect(third.track).toBe("var(--eb-line2)");
    expect(third.stroke).toBe("var(--eb-hold)");
    expect(third.dasharray).toBeCloseTo(circumference, 6);
    expect(third.offset).toBeCloseTo(circumference * (2 / 3), 6);
    // A quarter left is the last stretch: the arc takes the deny colour from there down.
    const quarter = arcOf(225);
    expect(quarter.stroke).toBe("var(--eb-deny)");
    expect(quarter.offset).toBeCloseTo(circumference * 0.75, 6);
    // Out of range either way is clamped, never drawn backwards or past a full circle.
    expect(arcOf(-5).offset).toBeCloseTo(circumference, 6);
    expect(arcOf(1200).offset).toBeCloseTo(0, 6);
    expect(arcOf(1200).stroke).toBe("var(--eb-hold)");
  });

  it("place each sparkline point by its value between the line's own low and high", () => {
    const { container } = render(<Sparkline title="Decisions this week" values={[3, 9, 4]} />);
    // Width 96 over three values is a step of 48; the low sits at y 26 and the high at y 2.
    expect(container.querySelector("polyline")?.getAttribute("points")).toBe("0,26 48,2 96,22");
    const { container: flat } = render(<Sparkline title="Nothing moved" values={[5, 5]} />);
    expect(flat.querySelector("polyline")?.getAttribute("points")).toBe("0,26 96,26");
  });
});
