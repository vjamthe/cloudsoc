# CloudSOC: AI-Driven Cloud Security Alert Triage

An event-driven AWS security pipeline that automatically triages GuardDuty findings. When a finding fires, a Lambda function enriches it with the involved identity's recent CloudTrail activity, asks Claude to assess it, and stores a structured verdict. Only the alerts worth a human's attention get escalated.

GuardDuty tells you *something* happened. CloudSOC decides whether it *matters*.

## Architecture

```
                   ┌──────────────┐
  API activity ──► │  CloudTrail  │ ◄──────────────── context lookup
                   └──────────────┘                         │
                                                            │
┌─────────────┐  finding  ┌───────────────┐  invoke  ┌──────┴───────────┐
│  GuardDuty  │ ────────► │  EventBridge  │ ───────► │      Lambda      │
└─────────────┘           │     rule      │          │ (cloudsoc-triage)│
                          └───────────────┘          └──────┬───────────┘
                                                            │
             ┌──────────────────┬──────────────────┬────────┴─────────┐
             ▼                  ▼                  ▼                  ▼
     ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
     │Secrets Manager│  │  Claude API   │  │   DynamoDB    │  │      SNS      │
     │   (API key)   │  │ (Sonnet 5.5)  │  │  (findings)   │  │ (P1/P2 email) │
     └───────────────┘  └───────────────┘  └───────────────┘  └───────────────┘
```

**Flow:**

1. GuardDuty raises a finding.
2. An EventBridge rule routes it to the triage Lambda.
3. The Lambda looks up the involved identity's last 6 hours of CloudTrail activity.
4. It sends the finding plus that context to Claude.
5. Claude returns a verdict, priority, blast radius, and recommended actions.
6. The result is stored in DynamoDB.
7. If the priority is P1 or P2, SNS emails an alert.

## Components

| Service | Role |
|---|---|
| GuardDuty | Threat detection; emits findings |
| CloudTrail | Records all API activity (multi-region, log file validation enabled) |
| EventBridge | Routes GuardDuty findings to the Lambda |
| Lambda (`cloudsoc-triage`, Python 3.12) | Enrichment, Claude call, storage, alerting |
| Claude API (Sonnet 5.5) | LLM triage via a structured tool call (`record_triage`) |
| DynamoDB (`cloudsoc-findings`) | Stores every finding and its triage result |
| SNS (`cloudsoc-alerts`) | Emails P1/P2 verdicts only |
| Secrets Manager | Holds the Claude API key, never in code, git, or Terraform state |

## Design Decisions

**Structured output.** Claude must answer by calling the `record_triage` tool, so the Lambda always gets JSON with a fixed schema. Required fields are validated before storing. Anything incomplete is marked `TRIAGE_FAILED` instead of being dropped.

**Context enrichment.** Every finding is enriched with the identity's recent CloudTrail activity. IAM users are looked up by username; assumed-role sessions are looked up by access key ID, so the triage sees what the actor actually did.

**Least privilege.** The Lambda role can read one secret, write to one table, publish to one topic, and call `cloudtrail:LookupEvents`. Nothing else. Attack simulations run under a dedicated assumed-role identity with temporary credentials, not static keys.

**Infrastructure as code.** Everything is defined in Terraform. `terraform destroy` removes the entire stack.

## Results

Validated with self-run attack simulations (defense evasion, root credential misuse, and reconnaissance from a threat-listed IP) against a benign baseline of the project's own deployment activity. On 21 scored findings:

| Metric | Value |
|---|---|
| Recall (real threats escalated) | **80%** |
| Noise suppression (benign activity held back) | **88%** |
| Overall accuracy | **86%** |
| Average cost per triage | **~2.2¢** |

**Severity lift:** root credential usage and CloudTrail tampering were both rated Low by GuardDuty, but the triage escalated them to P2. That is the core value of the system.

Full analysis and limitations: [eval/RESULTS.md](eval/RESULTS.md)

## Repository Layout

```
terraform/
  main.tf           provider, region, shared locals
  cloudtrail.tf     trail + locked-down log bucket
  guardduty.tf      detector
  lambda.tf         triage Lambda, IAM role, DynamoDB table
  eventbridge.tf    GuardDuty finding rule
  sns.tf            alert topic + email subscription
  secrets.tf        API key secret (value set outside Terraform)
  attacker.tf       assumed-role identity for attack simulations
lambda/triage/
  handler.py        enrichment, Claude triage, alerting
eval/
  RESULTS.md        evaluation write-up
  findings.csv      exported findings
```

## Deploy

Region: `us-east-2`. Requires an Anthropic API key with credits.

```bash
cd terraform
echo 'alert_email = "you@example.com"' > terraform.tfvars
terraform init
terraform apply
```

Then store the API key without it touching shell history:

```bash
read -s -p "API key: " K; echo
aws secretsmanager put-secret-value \
  --secret-id cloudsoc/anthropic-api-key \
  --secret-string file://<(printf %s "$K")
unset K
```

Confirm the SNS subscription from the email AWS sends you.

## Future Scope

- Auto-containment (for example, disabling a leaked access key) with human approval
- Permissions boundary on the deployer to replace broad IAM access
- Anomaly-based detections (privilege escalation, recon) once the account has baseline history
- Trimmed input and capped output lengths to reduce cost per triage
- Larger-scale evaluation across all finding types
