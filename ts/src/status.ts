/**
 * @file GET /auth/v1/status and GET /api/auth/v1/status: the state machine's answer for the stored row. It never
 * returns a token in any state (decisions 6 and 8): it exists so the dashboard, and anonymous visitors, can render
 * the two lifecycle banners without a session.
 */
import type { Credential, CredentialStore } from "./db/credential";
import { formatRfc3339, isZeroTime, type GoTime } from "./goTime";
import { TextAnswer } from "./http/json";
import { compute, type State } from "./state/machine";

/** The wire format. Dates are RFC 3339 as Go formats it; a member with nothing to say is absent, not empty. */
export interface StatusResponse {
  state: State;
  agentSymbol?: string;
  resetDate?: string;
  nextPredictedReset?: string;
}

const date = (t: GoTime | null): string | undefined => (t === null || isZeroTime(t) ? undefined : formatRfc3339(t));

/** toStatusResponse over compute: pure. */
export function statusFor(credential: Credential | undefined, nowMs: number): StatusResponse {
  const status = compute(
    {
      hasCredential: credential !== undefined,
      agentSymbol: credential?.agentSymbol ?? "",
      resetDate: credential?.resetDate ?? null,
      nextPredictedReset: credential?.nextPredictedReset ?? null,
      tokenExpired: credential?.tokenExpired ?? false,
    },
    nowMs,
  );
  const response: StatusResponse = { state: status.state };
  if (status.agentSymbol !== "") response.agentSymbol = status.agentSymbol;
  const resetDate = date(status.resetDate);
  if (resetDate !== undefined) response.resetDate = resetDate;
  const next = date(status.nextPredictedReset);
  if (next !== undefined) response.nextPredictedReset = next;
  return response;
}

/** getStatus: a failed read is a 500 with Go's sentence. */
export function readStatus(store: CredentialStore, nowMs: number): StatusResponse {
  let credential: Credential | undefined;
  try {
    credential = store.get();
  } catch (err) {
    throw new TextAnswer(500, `failed to load status: ${err instanceof Error ? err.message : String(err)}`);
  }
  return statusFor(credential, nowMs);
}
