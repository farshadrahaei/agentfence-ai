# AgentFence F1-F5 Evaluation (analyze-remediation)

- schema: agentfence-f1-f5-v2
- status: complete
- namespace: sandbox-gvisor-fresh

| factor | status | key evidence |
|---|---|---|
| F1 runtime placement | captured | target=target-gvisor-8d9db5f9-qd68b runtime=None |
| F2 attack-path containment | captured | scored=8 review_only=1 counts={'pass': 9, 'fail': 30, 'skip': 0} |
| F3 remediation effectiveness | improved | headline 1.693 -> 1.5736 |
| F4 artifact consistency | captured | artifacts=5 |
| F5 recoverability | restore_checkpoint_ready | rollback=True path='/Users/farshad/Library/Mobile Documents/com~apple~CloudDocs/Documents/Personal Folder/Graduate School/Marquette/Keyang/AI Security and Privacy/agentfence-plus-complete/generated_outputs/rollback_bundle_sandbox-gvisor-fresh_target-gvisor-8d9db5f9-qd68b_20260516T151436Z' |
