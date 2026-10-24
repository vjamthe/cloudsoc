# CloudSOC — Evaluation Results

AI-driven triage of AWS GuardDuty findings, enriched with CloudTrail context
and scored by Claude (Sonnet 5.5) into a verdict + priority + recommended actions.

## Method
- Ran self-directed attack simulations against a sandbox AWS account:
  defense evasion (CloudTrail logging disabled), credential misuse
  (root-credential usage), and reconnaissance from a threat-listed IP
  (assumed-role `backup-operator` enumerating IAM/S3/EC2/GuardDuty).
- Benign baseline: the project's own Terraform/CLI deployment activity,
  which tripped the same custom threat list.
- Each finding auto-enriched with the principal's prior CloudTrail activity,
  then triaged by Claude with forced structured (tool-call) output.
- Labeled by ground truth; "escalated" = Claude assigned P1/P2.

## Results (n=21)
| Metric | Value | |
|---|---|---|
| Recall (real threats escalated) | **80%** | 4/5 |
| Precision (escalations that were real) | **67%** | 4/6 |
| Noise suppression (benign held back) | **88%** | 14/16 |
| Overall accuracy | **86%** | 18/21 |
| Avg cost per triage | **~2.2¢** | 4,389 in / 1,310 out tokens |

Confusion matrix (escalate = P1/P2): TP=4, FN=1, FP=2, TN=14

## Severity lift — the core result
GuardDuty's raw severity vs. Claude's assigned priority. The triage escalated
serious-but-low-scored threats that a severity-only filter would bury:

| Finding | GuardDuty severity | Claude priority |
|---|---|---|
| Policy:IAMUser/RootCredentialUsage | 2.0 (Low) | P2 |
| Policy:IAMUser/RootCredentialUsage | 2.0 (Low) | P2 |
| Recon:IAMUser/MaliciousIPCaller.Custom | 5.0 (Medium) | P2 |
| Recon:IAMUser/MaliciousIPCaller.Custom | 5.0 (Medium) | P2 |
| Stealth:IAMUser/CloudTrailLoggingDisabled | 2.0 (Low) | P3 |

Root-credential usage and CloudTrail tampering both scored GuardDuty **2.0 (Low)**
but were escalated to **P2** — exactly the alerts a tier-1 analyst should see first.

## Limitations (honest scope)
- Small sample (21 scored findings); figures are illustrative, not production-scale.
- An initial simulation batch used self-identifying names (`sim-attacker`,
  `cloudsoc-test-list`), which Claude correctly flagged as test activity; those
  4 findings were excluded as invalid test data and the simulation was rerun
  with realistic naming. See future scope for a full-scale re-evaluation.
- Confidence scores run low because every attack shared a single weak signal
  (threat-listed IP); priority is the more meaningful output here.
