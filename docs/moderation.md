# Moderation Overview

Chorus moderation is token‑based and community‑driven. This document explains
the goals, current mechanisms, and planned safeguards to address harassment and
brigading risks while preserving anonymity.

## Goals

- Empower communities to curate content without deanonymizing users.
- Minimize friction for everyday participation while making coordinated abuse
  costly in tokens and effort.

## Mechanisms

- Moderation tokens: users periodically receive tokens that can be spent to
  open a case on a post. Token reset/issuance is handled by maintenance tasks.
- Community voting: cases progress from OPEN to CLEARED/HIDDEN based on
  thresholds from `core.settings` (`HARMFUL_HIDE_THRESHOLD`, etc.).
- Harmful vote tracking: separately tallies negative sentiment to aid discovery
  of problematic content even outside formal cases.

## Safeguards and Tensions

- Sybil pressure: anonymity enables cheap identities. Mitigations include PoW
  (with leases), token budgets, and per‑action replay protection to limit
  throughput.
- Harassment cycles: introduce cool‑downs on repeated harmful votes by the same
  user against the same target; consider community‑level quorum requirements.
- Small community dynamics: apply minimum community size thresholds before
  automated hiding takes effect to avoid small‑group capture.

## Roadmap Enhancements

- Add per‑author “harmful vote” cool‑downs and case auto‑throttling.
- Publish moderation transparency endpoints and audit exports.
- Explore optional, privacy‑preserving reputation signals (local to a
  community, non‑portable).

## Transparency Endpoints

- Community stats: `GET /api/v1/moderation/community/{internal_slug}/stats`  
  Aggregates cases (open/cleared/hidden), votes (harmful/not‑harmful), and top flagged posts.
- Community cases: `GET /api/v1/moderation/community/{internal_slug}/cases`  
  Lists recent moderation cases with anonymized summaries.
- Community ledger: `GET /api/v1/moderation/community/{internal_slug}/ledger`  
  Public, anonymized sequence of moderation triggers, case openings/closures.
- Global ledger: `GET /api/v1/moderation/ledger`  
  Same as above, across the entire network.

All endpoints use monotonic order indices and avoid timestamps to minimize metadata leakage while keeping state transitions auditable.
