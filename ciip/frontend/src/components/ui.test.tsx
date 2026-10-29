import { render, screen } from "@testing-library/react";
import { BarList } from "./charts";
import { SeverityBadge, TlpBadge } from "./ui";

describe("ui components", () => {
  it("renders severity in French", () => {
    render(<SeverityBadge value="critical" />);
    expect(screen.getByText("Critique").className).toContain("sev-critical");
  });

  it("renders TLP labels", () => {
    render(<TlpBadge value="amber+strict" />);
    expect(screen.getByText("TLP:AMBER+STRICT").className).toContain("tlp-amber-strict");
  });

  it("sorts bar lists by value", () => {
    render(<BarList data={{ low: 1, high: 5 }} labels={{ low: "Faible", high: "Élevée" }} />);
    const labels = screen.getAllByText(/Faible|Élevée/).map((n) => n.textContent);
    expect(labels).toEqual(["Élevée", "Faible"]);
  });
});
