# ICSAE parity fixtures

Each `*.input.json` is a full `dns-intelligence-*` scan; each `*.expected.json`
is the summary the CANONICAL Python engine produces for it. The Go engine is
held to these expectations by `TestCrossCheckPython` — two engines, one
catalog, identical verdicts.

Regenerate after ANY change to `normalize_input.py`, `evaluate.py`, or
`dns-to-controls.json`:

```bash
cd dns-eval
for f in ../go-server/internal/icsae/testdata/*.input.json; do
  base=$(basename "$f" .input.json)
  python3 Mappings/normalize_input.py "$f" /tmp/obs.json > /dev/null
  python3 Mappings/evaluate.py /tmp/obs.json "../go-server/internal/icsae/testdata/$base.expected.json" > /dev/null
done
```

Never hand-edit an `.expected.json` — it is a measurement of the Python
engine, and hand-editing it toward the Go engine's output inverts the parity
contract. The `dns-eval-harness` CI workflow enforces freshness: committed
expectations must match what the live Python pipeline produces (everything
except the `evaluated_at` timestamp), so a Python-engine change that ships
without regeneration fails CI instead of silently de-syncing the two engines.
