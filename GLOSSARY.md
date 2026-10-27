# auth-service

The vault and the center. Workspace-wide terms (vault, the center, universe reset, M2M token, scope) are in `meta/GLOSSARY.md`; this file holds the operator actions only auth-service knows.

## Language

**Restore Token**:
Handing auth-service a regenerated agent token for the same agent; no upstream call. Answers an expired token, not a universe reset.

**Reset Agent**:
Registering a new agent with the account token after a universe reset. Irreversible; never the same button as Restore Token (auth-design decision 8).
_Avoid_: re-register (as a UI label), restore
