# AgentFence F1-F5 Evaluation (analyze-remediation)

- schema: agentfence-f1-f5-v2
- status: complete
- namespace: sandbox-kata-fresh

| factor | status | key evidence |
|---|---|---|
| F1 runtime placement | captured | target=target-kata-cb4f6fd97-sqv8t runtime=None |
| F2 attack-path containment | captured | scored=6 review_only=1 counts={'pass': 7, 'fail': 32, 'skip': 0} |
| F3 remediation effectiveness | improved | headline 0.9254 -> 0.2687 |
| F4 artifact consistency | captured | artifacts=5 |
| F5 recoverability | restore_checkpoint_ready | rollback=True path='/Users/farshad/Library/Mobile Documents/com~apple~CloudDocs/Documents/Personal Folder/Graduate School/Marquette/Keyang/AI Security and Privacy/agentfence-plus-complete/generated_outputs/rollback_bundle_sandbox-kata-fresh_target-kata-cb4f6fd97-sqv8t_20260516T154048Z' |
