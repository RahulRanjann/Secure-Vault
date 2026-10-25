import { describe, expect, it } from "vitest";
import { isValidOAuthState } from "@/lib/oauth";

describe("OAuth state validation", () => {
  it("accepts matching state and rejects missing, replay-mismatched, or altered state", () => {
    const state = "a sufficiently random state value";
    expect(isValidOAuthState(state, state)).toBe(true);
    expect(isValidOAuthState(null, state)).toBe(false);
    expect(isValidOAuthState(state, undefined)).toBe(false);
    expect(isValidOAuthState(`${state}x`, state)).toBe(false);
    expect(isValidOAuthState("attacker-controlled", state)).toBe(false);
  });
});