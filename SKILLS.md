# Agent skills

Skills are the named capabilities an agent advertises. They are declared per-agent
in the topology (`entities/Agent/Agent.csv`, `skills` column) and defined once in
`entities/Skill/Skill.csv` (id, name, description, riskTier). Reva can then write
policies against a *skill* — e.g. "the intern may not use the customer-data skill" —
instead of against each individual tool.

## billing-support-agent

| Skill | Description | Risk | Backed by |
|-------|-------------|------|-----------|
| `billing` | Retrieve billing reports and invoice data for a customer | LOW | billing-mcp/get_billing_report |
| `compliance` | Check a customer's compliance and audit status | MEDIUM | billing-mcp/get_compliance_status |
| `customer-data` | Access a customer's personal (PII) data — highly sensitive | HIGH | billing-mcp/get_customer_pii |

## ticketing-agent (sub-agent)

| Skill | Description | Risk | Backed by |
|-------|-------------|------|-----------|
| `ticketing` | Open and close support tickets | LOW | ticketing-agent/create_ticket, close_ticket |

## booking-agent (sub-agent)

| Skill | Description | Risk | Backed by |
|-------|-------------|------|-----------|
| `booking` | Schedule callback appointment slots | LOW | booking-agent/list_slots, book_slot |

## Why skills matter for policy

Two policy styles this enables:
- **User → agent (on behalf of):** "billing-support-agent, acting on behalf of the
  intern, may not use the `customer-data` skill" — so the intern can pull a billing
  report but not PII, without denying the whole agent.
- **Agent → agent:** "billing-support-agent, on behalf of the intern, may not use the
  `ticketing` skill (i.e. may not delegate to the ticketing-agent)" — one user can
  book+invoice end to end, another is blocked at the ticketing hop.
