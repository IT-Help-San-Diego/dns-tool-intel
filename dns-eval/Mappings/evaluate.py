import json

with open("Mappings/dns-to-controls.json") as f:
    mappings = json.load(f)["mappings"]

with open("Mappings/normalized-from-dnstool.json") as f:
    data = json.load(f)

obs = data["observations"]

results = []

for m in mappings:
    applies = m.get("applies_when", [])
    if applies and not all(obs.get(k, False) for k in applies):
        results.append({"id": m["id"], "status": "not_applicable", "severity": m["severity"]})
        continue

    if "requires" in m:
        passed = all(obs.get(k, False) for k in m["requires"])
    elif "requires_any" in m:
        passed = any(obs.get(k, False) for k in m["requires_any"])
    else:
        passed = False

    results.append({
        "id": m["id"],
        "status": "passed" if passed else "failed",
        "severity": m["severity"]
    })

summary = {
    "domain": data["domain"],
    "source": data["source_file"],
    "high": [r["id"] for r in results if r["status"] == "failed" and r["severity"] == "high"],
    "medium": [r["id"] for r in results if r["status"] == "failed" and r["severity"] == "medium"],
    "low": [r["id"] for r in results if r["status"] == "failed" and r["severity"] == "low"],
    "passed": [r["id"] for r in results if r["status"] == "passed"],
    "na": [r["id"] for r in results if r["status"] == "not_applicable"]
}

print(json.dumps(summary, indent=2))
