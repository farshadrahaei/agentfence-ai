# AgentFence F1-F5 Evaluation (analyze-remediation)

- schema: agentfence-f1-f5-v2
- status: complete
- namespace: sandbox-cua-fresh

| factor | status | key evidence |
|---|---|---|
| F1 runtime placement | captured | target=target-cua-868d864fbc-77phz runtime=None |
| F2 attack-path containment | captured | scored=10 review_only=1 counts={'pass': 11, 'fail': 28, 'skip': 0} |
| F3 remediation effectiveness | improved | headline 4.1748 -> 4.0554 |
| F4 artifact consistency | captured | artifacts=5 |
| F5 recoverability | restore_checkpoint_ready | rollback=True path='/Users/farshad/Library/Mobile Documents/com~apple~CloudDocs/Documents/Personal Folder/Graduate School/Marquette/Keyang/AI Security and Privacy/agentfence-plus-complete/generated_outputs/rollback_bundle_sandbox-cua-fresh_target-cua-868d864fbc-77phz_20260516T143445Z' |
