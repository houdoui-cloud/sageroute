import { NEXT_STATUSES, fmtDuration, label, relative, STATUS } from "./format";

describe("format helpers", () => {
  it("formats durations at a readable scale", () => {
    expect(fmtDuration(null)).toBe("n/d");
    expect(fmtDuration(45)).toBe("45 min");
    expect(fmtDuration(300)).toBe("5.0 h");
    expect(fmtDuration(60 * 24 * 3)).toBe("3.0 j");
  });

  it("describes relative deadlines", () => {
    const now = new Date("2026-10-29T12:00:00Z");
    expect(relative("2026-10-29T14:00:00Z", now)).toBe("dans 2 h");
    expect(relative("2026-10-26T12:00:00Z", now)).toBe("il y a 3 j");
    expect(relative(null, now)).toBe("—");
  });

  it("falls back to the raw key for unknown labels", () => {
    expect(label(STATUS, "in_progress")).toBe("En traitement");
    expect(label(STATUS, "mystery")).toBe("mystery");
  });

  it("mirrors the backend transition table", () => {
    expect(NEXT_STATUSES.new).toContain("triaged");
    expect(NEXT_STATUSES.in_progress).not.toContain("closed");
    expect(NEXT_STATUSES.closed).toEqual(["in_progress"]);
  });
});
