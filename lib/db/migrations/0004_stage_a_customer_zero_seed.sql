BEGIN;

SET LOCAL row_security = off;

INSERT INTO workos.tenants (id, name)
VALUES ('10000000-0000-4000-8000-000000000001', 'W. Coleman & Co')
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.workspaces (
  id, tenant_id, name, workspace_type, security_domain
)
VALUES (
  '20000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  'Advisory Operations',
  'SMALL_PROFESSIONAL',
  'wcc-customer-zero-advisory'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.users (id, display_name)
VALUES
  ('30000000-0000-4000-8000-000000000001', 'Customer Zero Operator'),
  ('30000000-0000-4000-8000-000000000002', 'Customer Zero Director')
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.workspace_memberships (
  id, tenant_id, workspace_id, user_id, role
)
VALUES
  (
    '40000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000001',
    'OPERATOR'
  ),
  (
    '40000000-0000-4000-8000-000000000002',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000002',
    'PRINCIPAL'
  )
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.principals (
  id, tenant_id, workspace_id, principal_type, display_name
)
VALUES (
  '50000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  'PERSON',
  'Customer Zero Director'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.principal_user_links (
  id, tenant_id, workspace_id, principal_id, user_id
)
VALUES (
  '51000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000002'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.operator_assignments (
  id, tenant_id, workspace_id, operator_user_id, service_profile
)
VALUES (
  '60000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000001',
  'CUSTOMER_ZERO_EA'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.operator_assignment_principals (
  tenant_id, workspace_id, assignment_id, principal_id
)
VALUES (
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  '60000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000001'
)
ON CONFLICT DO NOTHING;

INSERT INTO workos.operator_assignment_action_scopes (
  id, tenant_id, workspace_id, assignment_id, action_class, authority_mode
)
VALUES
  (
    '61000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '60000000-0000-4000-8000-000000000001',
    'INTERNAL_TASK_STATE',
    'PREPARE'
  ),
  (
    '61000000-0000-4000-8000-000000000002',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '60000000-0000-4000-8000-000000000001',
    'EXTERNAL_COMMUNICATION',
    'BLOCKED'
  )
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.operator_assignment_data_scopes (
  id, tenant_id, workspace_id, assignment_id, scope_type, scope_key
)
VALUES (
  '62000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  '60000000-0000-4000-8000-000000000001',
  'WORKSPACE',
  'FOUNDATION_SEED_ONLY'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.work_objects (
  id, tenant_id, workspace_id, work_type, title,
  accountable_principal_id, owner_user_id
)
VALUES (
  '70000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  'FOUNDATION_READINESS',
  'Customer Zero foundation readiness',
  '50000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000001'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.tasks (
  id, tenant_id, workspace_id, work_object_id, intent, status,
  accountable_owner_user_id, next_action_owner_user_id, priority,
  completion_condition, waiting_on_type, waiting_on_key
)
VALUES
  (
    '71000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '70000000-0000-4000-8000-000000000001',
    'Verify tenant and workspace isolation',
    'IN_PROGRESS',
    '30000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000001',
    'HIGH',
    '{"type":"test_gate","suite":"stage_a_rls"}'::jsonb,
    NULL,
    NULL
  ),
  (
    '71000000-0000-4000-8000-000000000002',
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    '70000000-0000-4000-8000-000000000001',
    'Review Stage A completion report',
    'WAITING',
    '30000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000002',
    'NORMAL',
    '{"type":"human_confirmation","required_role":"PRINCIPAL"}'::jsonb,
    'STAGE_GATE',
    'STAGE_A_APPROVAL'
  )
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.commitments (
  id, tenant_id, workspace_id, work_object_id,
  promisor_principal_id, beneficiary_principal_id,
  commitment_text, status, completion_condition
)
VALUES (
  '72000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  '70000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000001',
  '50000000-0000-4000-8000-000000000001',
  'Do not proceed to Stage B without explicit approval',
  'OPEN',
  '{"type":"stage_boundary","required_approval":"STAGE_B"}'::jsonb
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO workos.portfolio_metadata_projection (
  id, tenant_id, workspace_id, assignment_id,
  category, urgency, age_seconds, status
)
VALUES (
  '73000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000001',
  '20000000-0000-4000-8000-000000000001',
  '60000000-0000-4000-8000-000000000001',
  'Foundation readiness',
  'HIGH',
  0,
  'IN_PROGRESS'
)
ON CONFLICT (id) DO NOTHING;

COMMIT;