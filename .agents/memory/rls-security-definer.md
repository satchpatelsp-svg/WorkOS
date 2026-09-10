---
name: Forced RLS security definers
description: The narrow role pattern required for membership-aware RLS helpers and control-plane job functions.
---

Membership-aware RLS helpers and control-plane job functions use a dedicated no-login `SECURITY DEFINER` role with `BYPASSRLS`; runtime, worker, migrator, and schema-owner roles must remain non-superuser and non-`BYPASSRLS`.

**Why:** Forced RLS also applies to the table owner. Without a narrow bypass role, a helper that must inspect memberships or claimed jobs is filtered by the same policies it is evaluating and fails closed for valid requests. Giving bypass to runtime or worker would destroy the isolation boundary.

**How to apply:** Keep definer functions fixed-search-path, free of dynamic SQL, minimally granted, and owned by the dedicated role. Expose only exact function signatures to runtime/worker roles; never grant those roles direct access to the cross-tenant job-envelope table.