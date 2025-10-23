# Roadmap

This document outlines near‑term priorities to address adoption and stability
concerns while keeping the anonymity‑first design intact.

## Q4 2025 (Alpha Hardening)

- Security: expand tests around auth challenge and PoW verification; publish
  SECURITY.md and threat model; prepare for external crypto review.
- UX: introduce adaptive PoW leases (configurable) to reduce friction on mobile
  while preserving replay protection.
- Docs: add API error semantics; moderation rationale; PoW design; contributor
  guide.

## Q1 2026 (Beta & Community Build‑out)

- Moderation: add cool‑downs for harmful votes; transparency endpoints; audit
  exports.
- Observability: basic metrics around PoW failures, replay rejections, and
  moderation outcomes.
- Clients: reference client for messaging with audited E2E primitives.

## Stretch

- Optional, privacy‑preserving local reputation signals; explore differential
  privacy for aggregated stats.
- Federated deployments; pluggable storage for messages.

