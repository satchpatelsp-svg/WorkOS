import { Router, type IRouter } from "express";
import { GetFoundationSummaryResponse } from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/foundation", (_req, res): void => {
  const data = GetFoundationSummaryResponse.parse({
    product: "Work OS",
    stage: "Stage A — Secure Foundation",
    mode: "foundation-preview",
    tenant: {
      id: "10000000-0000-4000-8000-000000000001",
      name: "W. Coleman & Co",
      kind: "Customer Zero tenant",
    },
    workspace: {
      id: "20000000-0000-4000-8000-000000000001",
      name: "Advisory Operations",
      kind: "Operational security domain",
    },
    principal: {
      id: "50000000-0000-4000-8000-000000000001",
      name: "Customer Zero Director",
      kind: "Represented principal",
    },
    security: [
      {
        name: "Tenant and workspace isolation",
        status: "ready",
        detail: "Application context and PostgreSQL RLS fail closed together.",
      },
      {
        name: "Access catalog",
        status: "ready",
        detail: "Context discovery returns authorised non-content metadata only.",
      },
      {
        name: "System jobs",
        status: "ready",
        detail: "Workers claim narrow envelopes before entering a scoped context.",
      },
      {
        name: "Microsoft connectivity",
        status: "gated",
        detail: "No authentication, Graph access, or live data is enabled in Stage A.",
      },
    ],
    workItems: [
      {
        id: "71000000-0000-4000-8000-000000000001",
        title: "Verify tenant and workspace isolation",
        status: "In progress",
        owner: "Customer Zero Operator",
        dueLabel: "Stage A gate",
        priority: "High",
      },
      {
        id: "71000000-0000-4000-8000-000000000002",
        title: "Review Stage A completion report",
        status: "Waiting",
        owner: "Customer Zero Director",
        dueLabel: "After verification",
        priority: "Normal",
      },
    ],
    recentActivity: [
      {
        id: "81000000-0000-4000-8000-000000000001",
        label: "Stage A architecture approved",
        actor: "Customer Zero Director",
        occurredAt: "2026-09-05T18:15:00.000Z",
      },
      {
        id: "81000000-0000-4000-8000-000000000002",
        label: "RLS and control-plane boundaries established",
        actor: "Work OS",
        occurredAt: "2026-09-05T18:31:00.000Z",
      },
    ],
  });

  res.json(data);
});

export default router;