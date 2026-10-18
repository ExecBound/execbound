// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { Button } from "../components/ui/Button";
import { useServerMutation } from "./mutation";

function Decide({ answer }: { answer: Promise<string> }) {
  const decision = useServerMutation({ mutationFn: () => answer });
  return (
    <>
      <Button
        variant="primary"
        disabled={decision.isPending}
        onClick={() => {
          decision.mutate();
        }}
      >
        Approve
      </Button>
      <output>{decision.data ?? (decision.isPending ? "waiting" : "idle")}</output>
    </>
  );
}

describe("a server mutation", () => {
  it("shows nothing before the server answers, and the button waits", async () => {
    let resolve: (value: string) => void = () => undefined;
    const answer = new Promise<string>((done) => {
      resolve = done;
    });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Decide answer={answer} />
      </QueryClientProvider>,
    );
    const button = screen.getByRole("button", { name: "Approve" });
    expect(screen.getByRole("status")).toHaveTextContent("idle");
    await userEvent.click(button);
    expect(screen.getByRole("status")).toHaveTextContent("waiting");
    expect(button).toBeDisabled();
    await act(async () => {
      resolve("APPROVED");
      await answer;
    });
    expect(await screen.findByText("APPROVED")).toBeInTheDocument();
    expect(button).toBeEnabled();
  });
});
