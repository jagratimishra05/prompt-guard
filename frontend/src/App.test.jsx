import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import * as api from "./api";

vi.mock("./api", () => ({
  getHealth: vi.fn(),
  scanText: vi.fn(),
  protectedGenerate: vi.fn(),
}));

const assessment = (decision) => ({
  decision,
  risk_score: decision === "ALLOW" ? 10 : decision === "REVIEW" ? 50 : 90,
  reason: `${decision} temporary mock assessment`,
  detectors: {
    rules: {
      status: "completed",
      prediction: decision === "ALLOW" ? "benign" : "malicious",
      evidence: decision === "ALLOW" ? [] : ["test_indicator"],
      reason: "Temporary mock detector result.",
    },
    ml: {
      status: "completed",
      prediction: decision === "ALLOW" ? "benign" : "malicious",
      malicious_probability: 0.1,
    },
    contextual: {
      status: "skipped",
      prediction: null,
      reason: "Temporary mock: contextual analysis was not run.",
    },
  },
});

beforeEach(() => {
  sessionStorage.clear();
  api.getHealth.mockResolvedValue({ status: "ok", service: "PromptGuard" });
  api.scanText.mockReset();
  api.protectedGenerate.mockReset();
});

describe("PromptGuard dashboard", () => {
  it("renders health and an ALLOW assessment", async () => {
    api.scanText.mockResolvedValue(assessment("ALLOW"));
    render(<App />);
    await screen.findByText("API connected");

    await userEvent.click(screen.getByRole("button", { name: "Security Scanner" }));
    await userEvent.type(screen.getByLabelText("Text to analyze"), "External text");
    await userEvent.click(screen.getByRole("button", { name: "Run security scan" }));

    expect(await screen.findByText("ALLOW")).toBeInTheDocument();
    expect(screen.getByText("10/100")).toBeInTheDocument();
    expect(screen.getByText(/Temporary mock assessment/)).toBeInTheDocument();
  });

  it.each(["REVIEW", "BLOCK"])("does not display generation for %s", async (decision) => {
    api.protectedGenerate.mockResolvedValue({
      ...assessment(decision),
      generated_response: null,
    });
    render(<App />);
    await screen.findByText("API connected");

    await userEvent.click(screen.getByRole("button", { name: "Protected Generation" }));
    await userEvent.type(screen.getByLabelText("Text to analyze"), "External text");
    await userEvent.type(screen.getByLabelText("Generation task"), "Summarize");
    await userEvent.click(screen.getByRole("button", { name: "Protected generate" }));

    expect(await screen.findByText(decision)).toBeInTheDocument();
    expect(screen.queryByText("Target provider response")).not.toBeInTheDocument();
  });

  it("labels synthetic generated output", async () => {
    const realPolicyAllow = {
      ...assessment("ALLOW"),
      reason: "ALLOW assessment",
      detectors: Object.fromEntries(
        Object.entries(assessment("ALLOW").detectors).map(([name, result]) => [
          name,
          { ...result, reason: undefined },
        ]),
      ),
    };
    api.protectedGenerate.mockResolvedValue({
      ...realPolicyAllow,
      generated_response: {
        provider: "offline_mock",
        is_mock: true,
        is_synthetic: true,
        text: "Synthetic test response",
      },
    });
    render(<App />);
    await screen.findByText("API connected");

    await userEvent.click(screen.getByRole("button", { name: "Protected Generation" }));
    await userEvent.type(screen.getByLabelText("Text to analyze"), "External text");
    await userEvent.type(screen.getByLabelText("Generation task"), "Summarize");
    await userEvent.click(screen.getByRole("button", { name: "Protected generate" }));

    expect(await screen.findByText("Synthetic test response")).toBeInTheDocument();
    expect(screen.getByText(/Synthetic mock output/)).toBeInTheDocument();
  });

  it("validates empty input and displays API errors", async () => {
    render(<App />);
    await screen.findByText("API connected");
    await userEvent.click(screen.getByRole("button", { name: "Security Scanner" }));
    await userEvent.click(screen.getByRole("button", { name: "Run security scan" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter text to scan.");

    api.scanText.mockRejectedValue(new Error("Security assessment unavailable."));
    await userEvent.type(screen.getByLabelText("Text to analyze"), "External text");
    await userEvent.click(screen.getByRole("button", { name: "Run security scan" }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("Security assessment unavailable."),
    );
  });

  it("records session scans and filters history by decision", async () => {
    api.scanText.mockResolvedValue(assessment("BLOCK"));
    render(<App />);
    await screen.findByText("API connected");
    await userEvent.click(screen.getByRole("button", { name: "Security Scanner" }));
    await userEvent.type(screen.getByLabelText("Text to analyze"), "Blocked external text");
    await userEvent.click(screen.getByRole("button", { name: "Run security scan" }));
    await screen.findByText("BLOCK");

    await userEvent.click(screen.getByRole("button", { name: "Scan History" }));
    await userEvent.click(screen.getByRole("button", { name: "ALLOW" }));
    expect(screen.getByText("No ALLOW scans in this session.")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "BLOCK" }));
    expect(screen.getByText("Blocked external text")).toBeInTheDocument();
  });
});
