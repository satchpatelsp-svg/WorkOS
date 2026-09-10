import type { AccessCatalogContext } from "@workspace/request-context";
import { withAccessCatalogContext } from "./context";

export interface AccessCatalogEntry {
  tenantId: string;
  tenantName: string;
  workspaceId: string;
  workspaceName: string;
  workspaceType: string;
  membershipRole: string;
  assignmentId: string | null;
  representedPrincipalId: string | null;
  representedPrincipalName: string | null;
  contextVersion: number;
  assignmentContextVersion: number | null;
}

export async function listAccessCatalog(
  context: AccessCatalogContext,
): Promise<AccessCatalogEntry[]> {
  return withAccessCatalogContext(context, async (_db, client) => {
    const result = await client.query<{
      tenant_id: string;
      tenant_name: string;
      workspace_id: string;
      workspace_name: string;
      workspace_type: string;
      membership_role: string;
      assignment_id: string | null;
      represented_principal_id: string | null;
      represented_principal_name: string | null;
      context_version: string;
      assignment_context_version: string | null;
    }>("select * from workos_security.get_access_catalog_for_current_user()");

    return result.rows.map((row) => ({
      tenantId: row.tenant_id,
      tenantName: row.tenant_name,
      workspaceId: row.workspace_id,
      workspaceName: row.workspace_name,
      workspaceType: row.workspace_type,
      membershipRole: row.membership_role,
      assignmentId: row.assignment_id,
      representedPrincipalId: row.represented_principal_id,
      representedPrincipalName: row.represented_principal_name,
      contextVersion: Number(row.context_version),
      assignmentContextVersion:
        row.assignment_context_version === null
          ? null
          : Number(row.assignment_context_version),
    }));
  });
}