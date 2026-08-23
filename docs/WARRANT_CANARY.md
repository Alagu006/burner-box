# BurnerBox Warrant Canary

**Last updated:** August 17, 2026

As of the date above, the BurnerBox project has not:

- Received any order or directive from any government, law enforcement, or intelligence agency to hand over user data, encryption keys, or server access.
- Been subject to any National Security Letter, FISA court order, or equivalent secret court proceeding.
- Been placed under any gag order preventing disclosure of such orders.
- Voluntarily provided any user data, message content, or metadata to any government entity.

This statement will be updated periodically. If this document is not updated for more than 90 days, readers should assume that either (a) the project is no longer actively maintained, or (b) the operators have received a directive they cannot disclose. **Absence of an update is not proof that a secret order has been received** — the project may simply be inactive.

## Limitations

This canary is a **transparency signal**, not a legal instrument. Be aware of the following:

- **Jurisdiction-specific legal status is unclear.** Whether a warrant canary has legal force varies by jurisdiction. Some courts have found that publishing a canary while withholding a secret order could itself constitute obstruction, while others treat canaries as protected speech. **TODO: Consult legal counsel for the specific jurisdictions where BurnerBox is deployed to confirm whether this canary has any legal standing.**
- **Canaries cannot be audited.** Unlike open-source code, there is no way to independently verify that this statement is truthful. It relies on the operator's willingness to maintain it honestly.
- **A canary does not protect against compelled decryption.** If the server operator is compelled to hand over encryption keys (e.g., for server-side encrypted files), this canary does not prevent that. It only addresses whether orders have been received.
- **Operational security limits apply.** If the operator is served with a secret order that includes a gag provision, they may be legally unable to update or remove this canary. The 90-day staleness threshold above is the intended mechanism for detecting this.
- **This project is a prototype.** It is not yet deployed in production. This canary reflects the project's intent and current state, not a commitment made by an operating organization.

## How to verify

The canary is served at `GET /api/v1/canary` as JSON. The raw markdown source is in `docs/WARRANT_CANARY.md` in the repository.
