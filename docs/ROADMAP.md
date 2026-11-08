# Roadmap

## Done

- [x] Tool-calling agent loop, sandboxed fake tools, planted fake secret
- [x] YAML scenario format with validation, 20 attacks and 7 benign controls
- [x] Mechanical judge (attack success, task success, message-sent checks)
- [x] Runner with repeated runs, JSON and Markdown output, progress display
- [x] Defense layers L1 to L4 (scanner, isolation, least privilege, simulated human)
- [x] Layer comparison report with chart, per-category table and residual attacks
- [x] Ollama client with clear errors (out of memory, timeouts, bad responses)
- [x] Tests (83), CI, deterministic mock model
- [x] "Model hijacked" measure next to strict attack success (found when a real 3B model was fooled but fumbled the tool arguments)
- [x] First real run: llama3.2:3b, 3 runs per scenario, comparison in the README

## Next

- [ ] Re-run L0 to L2 with the answer length cap so every layer uses the same client settings
- [ ] Do the full 5-run experiment instead of 3
- [ ] Run it with a second model and compare (even two small models is a good result)
- [ ] Read `results/*.json` for the hijacked runs, and write up what fooled the model
- [ ] Add a short demo recording or screenshot of the comparison to the README

## Strengthening the evaluation

- [ ] Write 10 or more held-out attacks after freezing the scanner patterns, and report L1 on those separately (the current L1 numbers are optimistic because the same author wrote both)
- [ ] Grow the library toward 40 scenarios: more exfiltration channels, multi-document attacks, attacks that need several tool calls
- [ ] Add adaptive attacks: take an attack that failed and try rephrased variants
- [ ] Add confidence intervals or at least report min/max over runs
- [ ] Compare against an existing open-source filter instead of only the hand-written scanner

## Stretch

- [ ] Ablation: run each layer on its own instead of cumulatively
- [ ] Model-based injection classifier as an alternative L1
- [ ] Multi-turn attacks where the payload arrives across several tool results