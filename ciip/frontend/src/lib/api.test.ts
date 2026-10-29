import { ApiError, api, qs, setTokens } from "./api";

describe("api client", () => {
  afterEach(() => vi.restoreAllMocks());

  it("builds query strings, skipping empty values", () => {
    expect(qs({ a: 1, b: "", c: undefined, d: ["x", "y"], e: true })).toBe("?a=1&d=x&d=y&e=true");
    expect(qs({})).toBe("");
  });

  it("sends the bearer token and JSON body", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    );
    setTokens("tok-123");
    await api("/incidents", { body: { title: "x" } });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/v1/incidents");
    expect((init as RequestInit).method).toBe("POST");
    expect((init!.headers as Record<string, string>).Authorization).toBe("Bearer tok-123");
  });

  it("surfaces FastAPI error details", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "Transition new → closed non autorisée" }), { status: 409 }),
    );
    setTokens("tok");
    await expect(api("/incidents/1/status", { body: {} })).rejects.toEqual(
      new ApiError(409, "Transition new → closed non autorisée"),
    );
  });

  it("joins validation errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: [{ msg: "champ requis" }, { msg: "trop court" }] }), { status: 422 }),
    );
    await expect(api("/x")).rejects.toThrow("champ requis ; trop court");
  });
});
