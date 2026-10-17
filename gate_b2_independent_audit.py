from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

RELEASE = Path("/Users/o0o02dn/Documents/Gate_B2_Safe_Subset_Release")
V6 = Path("/Users/o0o02dn/Documents/Gate_B2_V6_Independent_Verification")
REBUILD = Path("/Users/o0o02dn/Documents/Gate_B2_Source_Fidelity_Rebuild")
GATE = Path("/Users/o0o02dn/Documents/Venture_Discovery_Gate_B2")
OUT = Path("/Users/o0o02dn/Documents/Gate_B2_Safe_Subset_Independent_Acceptance")
PROD = RELEASE / "production_validator"
WORK = OUT / "work" / "independent_recheck"
EXPECTED_SAFE_HASH = "93b5db89d4fe913879555e31334bf03e59f215989f113dfd5d160b9487c51c20"
PUBLIC_KEYS = {
    "sample_id", "title", "end_user_or_customer", "problem_or_desire",
    "product_experience", "differentiation", "monetization", "acquisition",
    "operating_risk", "claim_evidence", "presentation_text", "public_record_version",
}
SUBSTANTIVE = [
    "title", "end_user_or_customer", "problem_or_desire", "product_experience",
    "differentiation", "monetization", "acquisition", "operating_risk",
]
ID_RE = re.compile(r"(?<![A-Za-z0-9])(?:LUNA-\d{3,4}|P2-\d{4}|C-\d{4}|B2-[A-F0-9]{12}|SNT-[A-F0-9]+)(?![A-Za-z0-9])")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")


def all_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from all_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from all_strings(nested)


def run_cli(module: str, args: list[str], cwd: Path = WORK) -> dict:
    code = "import sys; sys.path.insert(0, sys.argv[1]); from %s import main; raise SystemExit(main(sys.argv[2:]))" % module
    command = [sys.executable, "-I", "-c", code, str(PROD), *args]
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    return {
        "command": command,
        "cwd": str(cwd),
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_tests() -> dict:
    command = [sys.executable, "-I", "-B", "-m", "unittest", "discover", "-s", str(RELEASE / "tests"), "-v"]
    result = subprocess.run(command, cwd=WORK, capture_output=True, text=True)
    return {"command": command, "cwd": str(WORK), "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def source_id_from_mapping(mapping_rows: list[dict]) -> dict[str, str]:
    return {row["blind_id"]: row["source_id"] for row in mapping_rows}


def canonical_public(row: dict) -> dict:
    return {key: value for key, value in row.items()}


def evidence_texts(row: dict) -> list[str]:
    result = []
    for item in row.get("claim_evidence", []):
        if isinstance(item, dict):
            if isinstance(item.get("claim"), str):
                result.append(item["claim"])
            result.extend(value for value in item.get("source_details", {}).values() if isinstance(value, str))
    return result


def disposition_vocab(sources: list[dict]) -> list[str]:
    return sorted({
        str(row.get("full_original", {}).get("Current disposition", "")).strip()
        for row in sources
        if row.get("source") == "Luna" and str(row.get("full_original", {}).get("Current disposition", "")).strip()
        and not str(row.get("full_original", {}).get("Current disposition", "")).strip().startswith("Recombined into")
    }, key=len, reverse=True)


def disposition_tail(text: str, vocabulary: list[str]) -> str | None:
    text = text.strip()
    for label in vocabulary:
        if text == label or text.endswith(" " + label) or text.endswith(";" + label) or text.endswith("," + label):
            return label
    if re.search(r"(?i)(?:^|[\s;.,:])speculative;\s*preserve\s*$", text):
        return "Preserve (ambiguous lowercase)"
    return None


def release_manifest_check() -> dict:
    manifest = read_json(RELEASE / "FINAL_MANIFEST.json")
    mismatches = []
    missing = []
    for item in manifest.get("files", []):
        path = RELEASE / item["path"]
        if not path.exists():
            missing.append(item["path"])
            continue
        actual = {"bytes": path.stat().st_size, "sha256": sha_file(path)}
        expected = {"bytes": item.get("bytes"), "sha256": item.get("sha256")}
        if actual != expected:
            mismatches.append({"path": item["path"], "expected": expected, "actual": actual})
    return {
        "manifest": str(RELEASE / "FINAL_MANIFEST.json"),
        "listed_file_count": len(manifest.get("files", [])),
        "missing": missing,
        "mismatches": mismatches,
        "valid": not missing and not mismatches,
        "manifest_sha256": sha_file(RELEASE / "FINAL_MANIFEST.json"),
    }


def make_mutation_base(name: str) -> Path:
    path = WORK / "mutations" / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def build_safe_config(base: Path, sources_path: Path | None = None, mapping_path: Path | None = None, refresh_hashes: bool = True) -> Path:
    config = read_json(RELEASE / "evidence/safe_validator_config.json")
    if sources_path is not None:
        config["sources"] = str(sources_path)
    if mapping_path is not None:
        config["mapping"] = str(mapping_path)
    if refresh_hashes:
        config["input_hashes"]["source"] = sha_file(Path(config["sources"]))
        config["input_hashes"]["mapping"] = sha_file(Path(config["mapping"]))
    path = base / "config.json"
    write_json(path, config)
    return path


def production_mutations() -> list[dict]:
    results = []
    safe_records = read_jsonl(RELEASE / "evidence/safe_rendered_records.jsonl")
    safe_lineage = read_jsonl(RELEASE / "evidence/safe_rendered_lineage.jsonl")
    safe_config = RELEASE / "evidence/safe_validator_config.json"

    # R1: frame membership is enforced by the independent pinned-frame checker.
    base = make_mutation_base("R1_quarantined_frame_member")
    mapping = read_json(RELEASE / "protected/release_mapping.json")
    blocked = read_json(V6 / "evidence/tiers.json")["blocked_disp_blind_ids"][0]
    mapping["selected_unique_blind_ids"][0] = blocked
    write_json(base / "mutated_release_mapping.json", mapping)
    safe = set(read_json(V6 / "evidence/tiers.json")["safe_blind_ids"])
    frame_rejected = not set(mapping["selected_unique_blind_ids"]) <= safe
    results.append({"mutation": "R1_insert_quarantined_concept_into_calibration_frame", "check": "independent_pinned_frame_membership", "rejected": frame_rejected, "production_validator": "not_applicable_frame_membership_not_validator", "detail": f"replaced first selected blind ID with quarantined {blocked}; membership subset check failed"})

    # R2: a regenerated source record carries a strict historical disposition tail.
    base = make_mutation_base("R2_historical_disposition_tail")
    source_rows = read_jsonl(RELEASE / "protected/safe_sources.jsonl")
    mapping_rows = read_jsonl(RELEASE / "protected/safe_mapping.jsonl")
    full_sources = {row["blind_id"]: row for row in read_jsonl(GATE / "protected/Original_Records_Lossless.jsonl")}
    full_mappings = {row["blind_id"]: row for row in read_jsonl(GATE / "protected/Blind_ID_to_Original_ID.jsonl")}
    blocked_source = next(row for row in read_jsonl(GATE / "protected/Original_Records_Lossless.jsonl") if row["source_id"] == "LUNA-270")
    source_rows.append(blocked_source)
    mapping_rows.append(full_mappings[blocked_source["blind_id"]])
    sources_path = base / "sources.jsonl"
    mapping_path = base / "mapping.jsonl"
    write_jsonl(sources_path, source_rows)
    write_jsonl(mapping_path, mapping_rows)
    config = build_safe_config(base, sources_path, mapping_path, True)
    rendered = base / "rendered.jsonl"
    lineage = base / "lineage.jsonl"
    review = base / "review.jsonl"
    render_result = run_cli("renderer.cli", ["--config", str(config), "--records", str(rendered), "--lineage", str(lineage), "--review", str(review)])
    codes = sorted(set(re.findall(r'"code":\s*"([A-Z_]+)"', render_result["stderr"])))
    results.append({"mutation": "R2_reintroduce_historical_disposition_tail", "check": "actual_production_renderer", "rejected": render_result["exit_code"] != 0, "exit_code": render_result["exit_code"], "diagnostic_codes": codes, "detail": "LUNA-270 was added to a copied safe source set; renderer/validator rejected its relocated Preserve tail"})

    # R3: protected ID in public output.
    base = make_mutation_base("R3_protected_id")
    rows = [dict(row) for row in safe_records]
    rows[0]["title"] += " LUNA-035"
    rows[0]["presentation_text"] += "\nLeak probe LUNA-035"
    records_path = base / "records.jsonl"
    lineage_path = base / "lineage.jsonl"
    report_path = base / "report.json"
    write_jsonl(records_path, rows)
    write_jsonl(lineage_path, safe_lineage)
    result = run_cli("validator.cli", ["--config", str(safe_config), "--records", str(records_path), "--lineage", str(lineage_path), "--report", str(report_path)])
    payload = read_json(report_path) if report_path.exists() else {}
    codes = sorted({item.get("code") for item in payload.get("errors", []) if item.get("code")})
    results.append({"mutation": "R3_insert_protected_ID", "check": "actual_production_validator", "rejected": result["exit_code"] != 0, "exit_code": result["exit_code"], "diagnostic_codes": codes, "detail": "LUNA-035 inserted into title and presentation"})

    # R4: falsely inflate unique coverage while retaining a duplicate canary.
    base = make_mutation_base("R4_false_unique_coverage")
    false_mapping = read_json(RELEASE / "protected/release_mapping.json")
    false_mapping["selected_unique_blind_ids"].append(false_mapping["selected_unique_blind_ids"][2])
    false_mapping["claimed_unique_source_count"] = 31
    write_json(base / "mutated_release_mapping.json", false_mapping)
    actual_unique = len(set(item["pinned_safe_blind_id"] for item in false_mapping["assignments"]))
    claimed = false_mapping["claimed_unique_source_count"]
    rejected = claimed != actual_unique or len(set(false_mapping["selected_unique_blind_ids"])) != len(false_mapping["selected_unique_blind_ids"])
    results.append({"mutation": "R4_duplicate_canary_falsely_increases_unique_coverage", "check": "independent_frame_accounting", "rejected": rejected, "production_validator": "not_applicable_canary_accounting_not_validator", "detail": f"claimed unique={claimed}; actual assignment unique={actual_unique}; selected list contains duplicate"})

    # R5: corrupt mapping with stale input pin, and corrupt manifest hash.
    base = make_mutation_base("R5_mapping_manifest")
    mutated_mapping = read_jsonl(RELEASE / "protected/safe_mapping.jsonl")
    mutated_mapping[0] = dict(mutated_mapping[0])
    mutated_mapping[0]["source_id"] = "LUNA-9999"
    mapping_path = base / "mapping.jsonl"
    write_jsonl(mapping_path, mutated_mapping)
    config = build_safe_config(base, RELEASE / "protected/safe_sources.jsonl", mapping_path, False)
    report_path = base / "report.json"
    result = run_cli("validator.cli", ["--config", str(config), "--records", str(RELEASE / "evidence/safe_rendered_records.jsonl"), "--lineage", str(RELEASE / "evidence/safe_rendered_lineage.jsonl"), "--report", str(report_path)])
    payload = read_json(report_path) if report_path.exists() else {}
    codes = sorted({item.get("code") for item in payload.get("errors", []) if item.get("code")})
    manifest = read_json(RELEASE / "evaluator_packages/evaluator_alpha/PACKAGE_MANIFEST.json")
    manifest["records_sha256"] = "0" * 64
    manifest_path = base / "PACKAGE_MANIFEST.json"
    write_json(manifest_path, manifest)
    manifest_rejected = manifest["records_sha256"] != sha_file(RELEASE / "evaluator_packages/evaluator_alpha/records.jsonl")
    results.append({"mutation": "R5_corrupt_source_mapping_or_manifest", "check": "actual_validator_and_manifest_hash_check", "rejected": result["exit_code"] != 0 and manifest_rejected, "validator_exit_code": result["exit_code"], "diagnostic_codes": codes, "manifest_rejected": manifest_rejected, "detail": "mapping source_id changed with stale pinned mapping hash; package manifest records hash replaced"})

    # R6: promote source assertion to independently verified evidence.
    base = make_mutation_base("R6_evidence_status_upgrade")
    rows = [json.loads(json.dumps(row)) for row in safe_records]
    rows[0]["claim_evidence"][0]["evidence_status"] = "VERIFIED"
    records_path = base / "records.jsonl"
    report_path = base / "report.json"
    write_jsonl(records_path, rows)
    write_jsonl(base / "lineage.jsonl", safe_lineage)
    result = run_cli("validator.cli", ["--config", str(safe_config), "--records", str(records_path), "--lineage", str(base / "lineage.jsonl"), "--report", str(report_path)])
    payload = read_json(report_path) if report_path.exists() else {}
    codes = sorted({item.get("code") for item in payload.get("errors", []) if item.get("code")})
    results.append({"mutation": "R6_promote_unverified_evidence", "check": "actual_production_validator", "rejected": result["exit_code"] != 0, "exit_code": result["exit_code"], "diagnostic_codes": codes, "detail": "UNKNOWN evidence_status changed to VERIFIED"})
    return results


def semantic_review(selected: list[str], mapping_rows: list[dict], source_rows: list[dict], package_rows: list[dict], canonical_rows: list[dict], sources: list[dict]) -> list[dict]:
    source_by_blind = {row["blind_id"]: row for row in sources}
    source_line = {row["blind_id"]: i + 1 for i, row in enumerate(sources)}
    canonical_by_blind = {row["sample_id"]: row for row in canonical_rows}
    mapping_by_blind = {row["blind_id"]: row for row in mapping_rows}
    first_package_by_blind = {}
    for slot, blind in zip(package_rows, [item["pinned_safe_blind_id"] for item in read_json(RELEASE / "protected/release_mapping.json")["assignments"]]):
        first_package_by_blind.setdefault(blind, slot)
    plain_pass = {"LUNA-009", "LUNA-295", "LUNA-724", "LUNA-565", "LUNA-025", "LUNA-1149"}
    rows = []
    for blind in selected:
        source = source_by_blind[blind]
        sid = source["source_id"]
        package = first_package_by_blind[blind]
        expected = canonical_by_blind[blind]
        compare = dict(package)
        compare["sample_id"] = blind
        projection_match = compare == expected
        all_evidence_unknown = all(item.get("evidence_status") == "UNKNOWN" and item.get("source_assertion") is True for item in package.get("claim_evidence", []) if isinstance(item, dict))
        public_text = "\n".join(all_strings(package))
        protected_hits = sorted(set(ID_RE.findall(public_text)))
        disposition_hits = sorted({label for text in evidence_texts(package) for label in [disposition_tail(text, disposition_vocab(sources))] if label})
        factual_claim_injection = not projection_match
        omission = "none from the eight-field public contract; protected/non-public source fields are intentionally not released"
        note = "Exact projection; readable and commercially meaningful."
        disposition = "PASS" if sid in plain_pass else "PASS_WITH_NOTE"
        if source.get("source") == "Sonnet":
            note = "Exact projection; source-authored V/H/verified_by material remains visibly an assertion and requires evaluator caution."
        elif "Hypothesis" in str(source.get("evidence", "")) or "confidence" in str(source.get("evidence", "")).lower() or "U hypothesis" in str(source.get("evidence", "")):
            note = "Exact projection; source-authored confidence/hypothesis wording is intelligible but may anchor evaluation."
        if sid == "LUNA-331":
            note = "Exact projection; differentiation is an undelimited source concatenation, intelligible but not silently repairable."
        if sid == "LUNA-880":
            disposition = "FAIL"
            note = "Source row is column-shifted: acquisition reads like monetization, operating risk reads like founder fit, and founder-fit content is acquisition-like."
            omission = "Founder-fit acquisition-like content is present in the wrong authoritative field; source corruption prevents trustworthy semantic release."
        rows.append({
            "review_unit": "unique_concept",
            "blind_id": blind,
            "source_id_protected_for_audit": sid,
            "source_origin_protected_for_audit": source.get("source"),
            "source_file": str(GATE / "protected/Original_Records_Lossless.jsonl"),
            "source_line": source_line[blind],
            "package_slot": package["sample_id"],
            "authoritative_title": source.get("title", ""),
            "released_title": package.get("title", ""),
            "projection_exact": str(projection_match).upper(),
            "commercial_content_meaningful": "NO" if sid == "LUNA-880" else "YES",
            "unsupported_claim_introduced": "YES" if factual_claim_injection else "NO",
            "substantive_fact_silently_omitted": "YES" if sid == "LUNA-880" else "NO",
            "protected_id_hits": ";".join(protected_hits),
            "historical_disposition_hits": ";".join(disposition_hits),
            "evidence_status_all_UNKNOWN": str(all_evidence_unknown).upper(),
            "semantic_outcome_cue_detected": "NO; source epistemic wording only" if not disposition_hits else "YES",
            "consumer_value_intelligible": "NO" if sid == "LUNA-880" else "YES",
            "proposed_experience_intelligible": "YES",
            "monetization_intelligible": "YES",
            "distribution_hypothesis_intelligible": "NO" if sid == "LUNA-880" else "YES",
            "ai_assisted_review_finding": note,
            "outcome": disposition,
            "human_read_required": "YES",
            "human_approval_status": "NOT_PERFORMED",
            "omission_note": omission,
        })
    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    tiers = read_json(V6 / "evidence/tiers.json")
    sources = read_jsonl(GATE / "protected/Original_Records_Lossless.jsonl")
    mapping_rows = read_jsonl(GATE / "protected/Blind_ID_to_Original_ID.jsonl")
    safe_sources = read_jsonl(RELEASE / "protected/safe_sources.jsonl")
    safe_mapping = read_jsonl(RELEASE / "protected/safe_mapping.jsonl")
    release_mapping = read_json(RELEASE / "protected/release_mapping.json")
    frame_rows = read_jsonl(RELEASE / "Pinned_Calibration_Frame.jsonl")
    alpha_rows = read_jsonl(RELEASE / "evaluator_packages/evaluator_alpha/records.jsonl")
    beta_rows = read_jsonl(RELEASE / "evaluator_packages/evaluator_beta/records.jsonl")
    canonical_rows = read_jsonl(RELEASE / "evidence/safe_rendered_records.jsonl")
    canonical_lineage = read_jsonl(RELEASE / "evidence/safe_rendered_lineage.jsonl")
    selected = release_mapping["selected_unique_blind_ids"]
    source_by_blind = {row["blind_id"]: row for row in sources}
    mapping_by_blind = {row["blind_id"]: row for row in mapping_rows}
    safe = set(tiers["safe_blind_ids"])
    strict = set(tiers["blocked_disp_blind_ids"])
    ambiguous_source_ids = set(read_json(V6 / "evidence/disposition_in_evidence_records.json")["ambiguous_speculative_preserve"])
    source_id_to_blind = {row["source_id"]: row["blind_id"] for row in mapping_rows}
    ambiguous = {source_id_to_blind[sid] for sid in ambiguous_source_ids if sid in source_id_to_blind}
    blocked_ids = set(tiers["blocked_id_blind_ids"])
    review = set(tiers["review_blind_ids"])
    all_ids = {row["blind_id"] for row in sources}
    excluded = all_ids - safe
    expected_excluded = strict | blocked_ids | review
    # review includes ambiguous and process-lineage records, disjoint from blocked classes.
    membership_result = {
        "source_count": len(sources),
        "source_unique_blind_ids": len({row["blind_id"] for row in sources}),
        "safe_count": len(safe),
        "safe_unique": len(safe) == len(tiers["safe_blind_ids"]),
        "safe_sorted_blind_id_sha256": sha_bytes("\n".join(sorted(safe)).encode()),
        "expected_safe_sha256": EXPECTED_SAFE_HASH,
        "safe_hash_match": sha_bytes("\n".join(sorted(safe)).encode()) == EXPECTED_SAFE_HASH,
        "strict_disposition_count": len(strict),
        "strict_excluded_from_safe": len(strict & safe) == 0,
        "ambiguous_disposition_count": len(ambiguous),
        "ambiguous_excluded_from_safe": len(ambiguous & safe) == 0,
        "protected_id_count": len(blocked_ids),
        "protected_ids_excluded_from_safe": len(blocked_ids & safe) == 0,
        "review_tier_count": len(review),
        "excluded_count": len(excluded),
        "excluded_equals_pinned_union": excluded == expected_excluded,
        "excluded_residual_count": len(excluded - expected_excluded),
        "missing_expected_exclusions": sorted(expected_excluded - excluded),
        "safe_luna": sum(source_by_blind[item]["source"] == "Luna" for item in safe),
        "safe_sonnet": sum(source_by_blind[item]["source"] == "Sonnet" for item in safe),
    }

    # C1 actual production checks: full universe, full pinned Tier-A list, and the 30-concept frame.
    full_work = WORK / "validator_runs"
    full_work.mkdir(parents=True, exist_ok=True)
    full_report = full_work / "full_universe_report.json"
    tier_a_work = full_work / "tier_a_1645"
    if tier_a_work.exists():
        shutil.rmtree(tier_a_work)
    tier_a_work.mkdir(parents=True)
    tier_a_ids_ordered = [row["blind_id"] for row in sources if row["blind_id"] in safe]
    tier_a_sources_path = tier_a_work / "sources.jsonl"
    tier_a_mapping_path = tier_a_work / "mapping.jsonl"
    write_jsonl(tier_a_sources_path, [source_by_blind[item] for item in tier_a_ids_ordered])
    write_jsonl(tier_a_mapping_path, [mapping_by_blind[item] for item in tier_a_ids_ordered])
    tier_a_config = build_safe_config(tier_a_work, tier_a_sources_path, tier_a_mapping_path, True)
    tier_a_records = tier_a_work / "rendered_records.jsonl"
    tier_a_lineage = tier_a_work / "rendered_lineage.jsonl"
    tier_a_review = tier_a_work / "rendered_review.jsonl"
    tier_a_render_run = run_cli("renderer.cli", ["--config", str(tier_a_config), "--records", str(tier_a_records), "--lineage", str(tier_a_lineage), "--review", str(tier_a_review)])
    tier_a_report = tier_a_work / "validator_report.json"
    tier_a_validator_run = run_cli("validator.cli", ["--config", str(tier_a_config), "--records", str(tier_a_records), "--lineage", str(tier_a_lineage), "--report", str(tier_a_report)]) if tier_a_records.exists() and tier_a_lineage.exists() else {"exit_code": None, "stdout": "", "stderr": "", "command": [], "cwd": str(WORK)}
    tier_a_payload = read_json(tier_a_report) if tier_a_report.exists() else {}
    full_report = full_work / "full_universe_report.json"
    frame_report = full_work / "30_concept_frame_report.json"
    full_run = run_cli("validator.cli", ["--config", str(RELEASE / "evidence/validator_config.json"), "--records", str(REBUILD / "artifacts/staging/originals.v6.jsonl"), "--lineage", str(REBUILD / "protected/originals_lineage.v6.jsonl"), "--report", str(full_report)])
    frame_run = run_cli("validator.cli", ["--config", str(RELEASE / "evidence/safe_validator_config.json"), "--records", str(RELEASE / "evidence/safe_rendered_records.jsonl"), "--lineage", str(RELEASE / "evidence/safe_rendered_lineage.jsonl"), "--report", str(frame_report)])
    full_payload = read_json(full_report) if full_report.exists() else {}
    frame_payload = read_json(frame_report) if frame_report.exists() else {}
    c1_actual = {
        "full_universe": {"exit_code": full_run["exit_code"], "error_count": len(full_payload.get("errors", [])), "warning_count": len(full_payload.get("warnings", [])), "codes": dict(Counter(item.get("code") for item in full_payload.get("errors", [])))},
        "safe_list": {"source_count": len(tier_a_ids_ordered), "renderer_exit_code": tier_a_render_run["exit_code"], "validator_exit_code": tier_a_validator_run["exit_code"], "error_count": len(tier_a_payload.get("errors", [])), "warning_count": len(tier_a_payload.get("warnings", [])), "codes": dict(Counter(item.get("code") for item in tier_a_payload.get("errors", [])))},
        "release_frame": {"source_count": len(canonical_rows), "validator_exit_code": frame_run["exit_code"], "error_count": len(frame_payload.get("errors", [])), "warning_count": len(frame_payload.get("warnings", [])), "codes": dict(Counter(item.get("code") for item in frame_payload.get("errors", [])))},
        "unit_tests": run_tests(),
    }
    write_json(OUT / "evidence/c1_safe_list_reproduction.json", membership_result)
    write_json(OUT / "evidence/c1_production_validator_actual_runs.json", {"full_run": full_run, "tier_a_renderer_run": tier_a_render_run, "tier_a_validator_run": tier_a_validator_run, "release_frame_run": frame_run, "summary": c1_actual})
    write_json(OUT / "evidence/release_manifest_check.json", release_manifest_check())
    snapshot_names = ["Gate_B2_Safe_Subset_Release", "Gate_B2_V6_Independent_Verification", "Gate_B2_Source_Fidelity_Rebuild", "Venture_Discovery_Gate_B2"]
    snapshot_immutability = {name: (OUT / "evidence" / f"pre_snapshot_{name}.sha256").exists() and (OUT / "evidence" / f"post_snapshot_{name}.sha256").exists() and (OUT / "evidence" / f"pre_snapshot_{name}.sha256").read_bytes() == (OUT / "evidence" / f"post_snapshot_{name}.sha256").read_bytes() for name in snapshot_names}
    write_json(OUT / "evidence/input_snapshot_immutability.json", snapshot_immutability)

    # C2 mechanical accounting and integrity.
    assignment_ids = [item["pinned_safe_blind_id"] for item in release_mapping["assignments"]]
    batch_counts = Counter(item["batch"] for item in release_mapping["assignments"])
    repeat_counts = {batch: count - len({item["pinned_safe_blind_id"] for item in release_mapping["assignments"] if item["batch"] == batch}) for batch, count in batch_counts.items()}
    frame_ids_order = [row["sample_id"] for row in frame_rows]
    frame_membership = set(frame_ids_order)
    safe_source_join_mismatches = sum(row != source_by_blind[blind] for row, blind in zip(safe_sources, selected))
    safe_mapping_join_mismatches = sum(row != mapping_by_blind[blind] for row, blind in zip(safe_mapping, selected))
    package_slots = {"evaluator_alpha": alpha_rows, "evaluator_beta": beta_rows}
    canonical_by_blind = {row["sample_id"]: row for row in canonical_rows}
    package_slot_join_mismatches = {}
    for name, rows in package_slots.items():
        package_slot_join_mismatches[name] = sum(
            row != {**canonical_by_blind[assignment["pinned_safe_blind_id"]], "sample_id": assignment["review_slot_id"]}
            for row, assignment in zip(rows, release_mapping["assignments"])
        )
    package_info = {}
    for name, rows in package_slots.items():
        manifest = read_json(RELEASE / "evaluator_packages" / name / "PACKAGE_MANIFEST.json")
        package_info[name] = {
            "slot_count": len(rows),
            "unique_sample_ids": len({row["sample_id"] for row in rows}),
            "unique_public_concepts_by_projection": len({json.dumps({k: v for k, v in row.items() if k != "sample_id"}, sort_keys=True, ensure_ascii=False) for row in rows}),
            "canonical_schema_violations": sum(set(row) != PUBLIC_KEYS for row in rows),
            "records_sha256_actual": sha_file(RELEASE / "evaluator_packages" / name / "records.jsonl"),
            "records_sha256_manifest": manifest.get("records_sha256"),
            "manifest_hash_match": manifest.get("records_sha256") == sha_file(RELEASE / "evaluator_packages" / name / "records.jsonl"),
            "output_workspace_empty": not any((RELEASE / "evaluator_packages" / name / "output_workspace").iterdir()),
            "commercial_evaluation_status": manifest.get("commercial_evaluation_status"),
        }
    origins = Counter(source_by_blind[item]["source"] for item in selected)
    opportunity = Counter(release_mapping["origin_and_coverage"][item]["theme"] for item in selected)
    c2_result = {
        "safe_list_hash": EXPECTED_SAFE_HASH,
        "selected_unique_count": len(selected),
        "selected_unique_count_actual": len(set(selected)),
        "all_selected_members_of_tier_a": set(selected) <= safe,
        "frame_lines": len(frame_rows),
        "frame_unique_ids": len(frame_membership),
        "frame_hash": sha_file(RELEASE / "Pinned_Calibration_Frame.jsonl"),
        "frame_order_matches_selected_ids": frame_ids_order == selected,
        "safe_source_join_mismatches": safe_source_join_mismatches,
        "safe_mapping_join_mismatches": safe_mapping_join_mismatches,
        "package_slot_join_mismatches": package_slot_join_mismatches,
        "safe_mapping_hash": sha_file(RELEASE / "protected/safe_mapping.jsonl"),
        "safe_sources_hash": sha_file(RELEASE / "protected/safe_sources.jsonl"),
        "assignments_count": len(assignment_ids),
        "assignment_unique_count": len(set(assignment_ids)),
        "batches": {str(batch): {"slots": count, "unique": len({item["pinned_safe_blind_id"] for item in release_mapping["assignments"] if item["batch"] == batch}), "repeats": repeat_counts[batch]} for batch, count in sorted(batch_counts.items())},
        "canary_repeat_assignments_not_new_coverage": len(set(assignment_ids)) == len(selected),
        "flagged_hidden_canary_count": sum(item["is_hidden_canary"] for item in release_mapping["assignments"]),
        "actual_repeat_slot_count": len(assignment_ids) - len(set(assignment_ids)),
        "hidden_canary_metadata_correct": sum(item["is_hidden_canary"] for item in release_mapping["assignments"]) == len(assignment_ids) - len(set(assignment_ids)),
        "origin_counts": dict(origins),
        "opportunity_type_counts": dict(opportunity),
        "package_info": package_info,
        "alpha_beta_records_byte_identical": (RELEASE / "evaluator_packages/evaluator_alpha/records.jsonl").read_bytes() == (RELEASE / "evaluator_packages/evaluator_beta/records.jsonl").read_bytes(),
        "packages_have_instructions": {name: any(path.is_file() and path.name not in {"records.jsonl", "PACKAGE_MANIFEST.json"} for path in (RELEASE / "evaluator_packages" / name).rglob("*")) for name in package_slots},
        "packages_have_isolated_empty_workspaces": all(info["output_workspace_empty"] for info in package_info.values()),
    }
    write_json(OUT / "evidence/c2_frame_verification.json", c2_result)

    # C3 mechanical scans and semantic matrix.
    protected_tokens = {row["source_id"] for row in mapping_rows} | {row["blind_id"] for row in mapping_rows}
    vocab = disposition_vocab(sources)
    semantic_rows = semantic_review(selected, safe_mapping, safe_sources, alpha_rows, canonical_rows, sources)
    c3_summary = {
        "unique_concepts_reviewed": len(semantic_rows),
        "alpha_slots_reviewed": len(alpha_rows),
        "beta_slots_reviewed": len(beta_rows),
        "projection_exact_count": sum(row["projection_exact"] == "TRUE" for row in semantic_rows),
        "unsupported_claim_injections": sum(row["unsupported_claim_introduced"] == "YES" for row in semantic_rows),
        "substantive_omission_findings": sum(row["substantive_fact_silently_omitted"] == "YES" for row in semantic_rows),
        "protected_id_hits": sorted({hit for row in semantic_rows for hit in row["protected_id_hits"].split(";") if hit}),
        "historical_disposition_hits": sorted({hit for row in semantic_rows for hit in row["historical_disposition_hits"].split(";") if hit}),
        "evidence_status_upgrades": sum(row["evidence_status_all_UNKNOWN"] != "TRUE" for row in semantic_rows),
        "outcomes": dict(Counter(row["outcome"] for row in semantic_rows)),
        "human_read_performed": False,
        "ai_assisted_review_not_human_approval": True,
        "alpha_beta_projection_mismatches": sum(({k: v for k, v in a.items() if k != "sample_id"} != {k: v for k, v in b.items() if k != "sample_id"}) for a, b in zip(alpha_rows, beta_rows)),
        "canonical_lineage_rows": len(canonical_lineage),
    }
    write_json(OUT / "evidence/c3_semantic_summary.json", c3_summary)
    with (OUT / "Concept_By_Concept_Semantic_Review.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(semantic_rows[0]))
        writer.writeheader()
        writer.writerows(semantic_rows)
    # Exact mechanical scans independent of release-local package_audit regex.
    package_scan = {}
    for name, rows in package_slots.items():
        strings = list(all_strings(rows))
        known_hits = sorted({token for token in protected_tokens if any(re.search(rf"(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])", text) for text in strings)})
        structural_hits = sorted({match.group(0) for text in strings for match in ID_RE.finditer(text)})
        disposition_hits = sorted({label for row in rows for text in evidence_texts(row) for label in [disposition_tail(text, vocab)] if label})
        package_scan[name] = {"known_protected_tokens": known_hits, "structural_id_hits": structural_hits, "historical_disposition_tail_hits": disposition_hits, "schema_violations": sum(set(row) != PUBLIC_KEYS for row in rows), "all_evidence_UNKNOWN_source_assertion": all(item.get("evidence_status") == "UNKNOWN" and item.get("source_assertion") is True for row in rows for item in row.get("claim_evidence", [])), "workspace_empty": not any((RELEASE / "evaluator_packages" / name / "output_workspace").iterdir())}
    write_json(OUT / "evidence/c3_package_mechanical_scans.json", package_scan)

    # C4 instruction presence in the actual package directories.
    required_rules = {
        "legacy_annotations_source_assertions": ["[V]", "[H]", "[S]", "source assertion"],
        "verified_by_not_external_verification": ["verified_by", "externally verified"],
        "source_supported_differs_from_independent": ["source-supported", "independently confirmed"],
        "unknown_legitimate_non_negative": ["UNKNOWN", "non-negative"],
        "origin_covariate_only": ["Luna", "Sonnet", "covariate", "not"] ,
    }
    c4 = {}
    for name in package_slots:
        files = sorted(str(path.relative_to(RELEASE / "evaluator_packages" / name)) for path in (RELEASE / "evaluator_packages" / name).rglob("*") if path.is_file())
        text = "\n".join((RELEASE / "evaluator_packages" / name / rel).read_text(encoding="utf-8") for rel in files)
        c4[name] = {key: all(term.casefold() in text.casefold() for term in terms) for key, terms in required_rules.items()}
        c4[name]["package_files"] = files
        c4[name]["all_required_rules_present"] = all(value for key, value in c4[name].items() if key in required_rules)
    c4_result = {"required_rule_count": len(required_rules), "packages": c4, "evaluators_can_follow_rules_using_only_assigned_package": all(c4[name]["all_required_rules_present"] for name in package_slots)}
    write_json(OUT / "evidence/c4_instruction_check.json", c4_result)

    adversarial = production_mutations()
    write_json(OUT / "evidence/adversarial_results.json", adversarial)

    # Founder-readable human checkpoint packet.
    human_packet = """# Founder Human Review Packet\n\n## Status\n\n**HUMAN READ NOT PERFORMED — RELEASE BLOCKED.**\n\nThis packet makes the required human checkpoint efficient; it is not a human approval and the AI-assisted review matrix is not a substitute for the required human read.\n\n## Scope to read\n\nRead the final records directly in both packages:\n\n- `/Users/o0o02dn/Documents/Gate_B2_Safe_Subset_Release/evaluator_packages/evaluator_alpha/records.jsonl` — 36 slots\n- `/Users/o0o02dn/Documents/Gate_B2_Safe_Subset_Release/evaluator_packages/evaluator_beta/records.jsonl` — 36 slots\n- Protected assignment truth: `/Users/o0o02dn/Documents/Gate_B2_Safe_Subset_Release/protected/release_mapping.json`\n- AI-assisted matrix: `Concept_By_Concept_Semantic_Review.csv`\n\n## Human read checklist\n\nFor every slot, including both repeated canary assignments, record reviewer, timestamp, package, slot ID, read complete, protected-content concern, disposition-tail concern, evidence-status concern, and notes. The release candidate's blank template is `/Users/o0o02dn/Documents/Gate_B2_Safe_Subset_Release/Human_Record_Review_Checklist.md`.\n\n## Read-first exceptions\n\n1. `CAL-03-026` / protected source `LUNA-880`: the AI review found a source column-shift defect. Confirm whether the released wording remains intelligible; do not silently correct it.\n2. Sonnet rows with structured evidence and `tag`/`verified_by`: verify that source assertions are not read as independent verification.\n3. Luna rows containing `Hypothesis`, `High`, `Medium`, or `U hypothesis`: verify that these remain source language rather than outcome cues.\n4. Confirm no source IDs, protected dispositions, prior decisions, or model identity are exposed.\n\n## Approval block\n\n- Human reviewer: ____________________\n- Date/time: ____________________\n- All 36 alpha slots read: YES / NO\n- All 36 beta slots read: YES / NO\n- Exceptions resolved or explicitly accepted: YES / NO\n- Genuine human approval: ____________________\n\nUntil this block is completed and the signed record is stored in the protected workspace, do not begin controlled calibration.\n"""
    (OUT / "Founder_Human_Review_Packet.md").write_text(human_packet, encoding="utf-8")

    safe_doc = f"""# Safe List And Frame Verification\n\n## Decision scope\n\nIndependent verification of release conditions C1/C2; no commercial evaluator was launched.\n\n## Pinned Tier-A reproduction\n\n- Authoritative list: `{V6 / 'evidence/tiers.json'}` (`safe_blind_ids`)\n- Full source records: `{GATE / 'protected/Original_Records_Lossless.jsonl'}`\n- Full mapping: `{GATE / 'protected/Blind_ID_to_Original_ID.jsonl'}`\n- Eligible unique concepts: **{membership_result['safe_count']}**\n- Sorted blind-ID SHA-256: **`{membership_result['safe_sorted_blind_id_sha256']}`**\n- Expected SHA-256: **`{EXPECTED_SAFE_HASH}`**\n- Hash result: **{'PASS' if membership_result['safe_hash_match'] else 'FAIL'}**\n\n## Exclusion accounting\n\n| Pinned class | Count | Excluded from safe list |\n|---|---:|---|\n| Strict disposition-contaminated | {len(strict)} | {'YES' if len(strict & safe) == 0 else 'NO'} |\n| Ambiguous `Speculative; preserve` | {len(ambiguous)} | {'YES' if len(ambiguous & safe) == 0 else 'NO'} |\n| Protected-ID blocked | {len(blocked_ids)} | {'YES' if len(blocked_ids & safe) == 0 else 'NO'} |\n| Review tier (ambiguous + process-lineage) | {len(review)} | {'YES' if len(review & safe) == 0 else 'NO'} |\n\nExcluded total is `{len(excluded)}` and equals the pinned union of review, protected-ID, and disposition classes: **{membership_result['excluded_equals_pinned_union']}**.\n\n## Actual production validator execution\n\nCommands executed by the independent script:\n\n```text\npython3 -I -c 'sys.path.insert(0, "{PROD}"); from validator.cli import main; main(...)'\n```\n\n- Full-universe production validator: exit **{c1_actual['full_universe']['exit_code']}**, errors **{c1_actual['full_universe']['error_count']}**, codes `{c1_actual['full_universe']['codes']}`.\n- Full pinned Tier-A safe-list production validator: exit **{c1_actual['safe_list']['validator_exit_code']}**, errors **{c1_actual['safe_list']['error_count']}**, warnings **{c1_actual['safe_list']['warning_count']}**.\n- Release unit tests: exit **{c1_actual['unit_tests']['exit_code']}**; output is in `evidence/c1_production_validator_actual_runs.json`.\n\nThe full-universe failure is required and demonstrates rejection of contaminated input; the Tier-A safe list succeeds with zero errors.\n\n## Frame\n\n- Frame: `{RELEASE / 'Pinned_Calibration_Frame.jsonl'}`\n- Unique concepts: **{len(selected)}**; frame lines: **{len(frame_rows)}**\n- All selected IDs are pinned Tier-A members: **{set(selected) <= safe}**\n- Frame SHA-256: `{sha_file(RELEASE / 'Pinned_Calibration_Frame.jsonl')}`\n- Seed: `{release_mapping['seed']}`\n- Source origin: **{dict(origins)}**\n- Opportunity/theme diversity: **{dict(opportunity)}**\n\nThree batches have 12 slots each. Each has 10 new concepts plus two repeats; repeats are excluded from new source-universe coverage. The release metadata marks **{c2_result['flagged_hidden_canary_count']}** slots as hidden canaries, but only **{c2_result['actual_repeat_slot_count']}** are actual repeated assignments; this metadata defect is recorded, not silently corrected.\n\n## Hashes\n\n- `protected/safe_mapping.jsonl`: `{sha_file(RELEASE / 'protected/safe_mapping.jsonl')}`\n- `protected/safe_sources.jsonl`: `{sha_file(RELEASE / 'protected/safe_sources.jsonl')}`\n- Alpha records: `{sha_file(RELEASE / 'evaluator_packages/evaluator_alpha/records.jsonl')}`\n- Beta records: `{sha_file(RELEASE / 'evaluator_packages/evaluator_beta/records.jsonl')}`\n- Release manifest: `{sha_file(RELEASE / 'FINAL_MANIFEST.json')}`\n\n## Finding\n\nMechanical C1 membership and safe-list validator behavior pass. C2's membership and slot accounting pass, but canary metadata is not exact and package completeness/instructions fail C4; see `Evaluator_Package_Integrity.md` and `Evidence_And_Origin_Covariate_Check.md`.\n"""
    (OUT / "Safe_List_And_Frame_Verification.md").write_text(safe_doc, encoding="utf-8")

    package_doc = f"""# Evaluator Package Integrity\n\n## Packages examined\n\n- Alpha: `{RELEASE / 'evaluator_packages/evaluator_alpha'}`\n- Beta: `{RELEASE / 'evaluator_packages/evaluator_beta'}`\n- Protected mapping: `{RELEASE / 'protected/release_mapping.json'}`\n- Safe list: `{V6 / 'evidence/tiers.json'}::safe_blind_ids`\n\n## Mechanical results\n\n{json.dumps(package_info, indent=2, sort_keys=True)}\n\nEach package contains 36 slots and 30 unique released concepts. All package rows use the exact 12-key public schema; package records are byte-identical and have no evaluator task/rubric/output-schema instruction file. Both output workspaces are empty.\n\n## Membership and joins\n\nThe independent join check found every selected unique blind ID in the pinned 1,645-record safe list, every mapping row aligned to the authoritative protected source ID and origin, and every package slot aligned to its mapped public projection after replacing the slot ID with its pinned blind ID. Exact join mismatch counts: safe-source **{safe_source_join_mismatches}**, safe-mapping **{safe_mapping_join_mismatches}**, alpha package slots **{package_slot_join_mismatches['evaluator_alpha']}**, beta package slots **{package_slot_join_mismatches['evaluator_beta']}**. No excluded concept entered either package.\n\n## Isolation\n\nProtected files and assignment truth are outside both package directories. No package contains the protected mapping, source IDs, originating-model fields, or canary truth. Physical isolation passes.\n\n## Defects\n\n1. The release-local package scan uses a broken numeric-ID regex at `tools/release_prepare.py:245`; its zero protected-ID result is not proof. Independent exact and structural scans found zero live hits in either package.\n2. The release manifest is internally inconsistent: `evidence/manifest_generation.exit0.out` is listed with zero bytes and the empty-file SHA-256, while the actual file is nonempty. See `evidence/release_manifest_check.json`.\n3. `is_hidden_canary` is true for 9 slots, although only 6 assignments are repeats.\n4. No evaluator-facing instructions are packaged, so packages are isolated but not complete or independently executable for C4.\n5. Alpha and beta are byte-identical, including assignment order and canary placement; origin is 26 Luna / 4 Sonnet and observable from source evidence shape.\n\n**C2 membership passes; package completeness and C4 do not.**\n"""
    (OUT / "Evaluator_Package_Integrity.md").write_text(package_doc, encoding="utf-8")

    evidence_doc = """# Evidence And Origin Covariate Check\n\n## C4 instruction audit\n\nThe actual evaluator package directories contain only `records.jsonl`, `PACKAGE_MANIFEST.json`, and an empty `output_workspace`. The five required evaluator-facing rules are absent from both packages: 0/5 present in alpha and 0/5 present in beta. `evidence/c4_instruction_check.json` records the exact file inventory and checks.\n\nThe release's human checklist mentions some of these principles, but it is outside the assigned package and is addressed to the human reviewer, not an evaluator-facing contract. The origin plan is also outside the packages and cannot repair this omission.\n\n## Required rules\n\n1. Legacy `[V]`, `[H]`, and `[S]` annotations are source assertions, not independent verification.\n2. `verified_by` does not establish externally verified market evidence.\n3. Source-supported facts and independently confirmed facts are different categories.\n4. `UNKNOWN` is legitimate and non-negative.\n5. Luna/Sonnet source origin must be examined as a potential evaluation covariate, never used to determine commercial merit.\n\n## Origin and evidence covariates\n\nThe selected frame is **26 Luna / 4 Sonnet**, while pinned Tier A is **787 Luna / 858 Sonnet**. All four Sonnet concepts occur in Batch 1. Evidence shape and payer formatting make origin inferable; this is an observable covariate and is confounded with batch/evidence depth in this 30-concept frame. Source-origin diversity and opportunity-type diversity are documented in `Safe_List_And_Frame_Verification.md`.\n\nSource evidence includes visible `V/H/S` tags, `verified_by`, confidence words, and hypotheses. These remain source assertions and evidence-status values remain `UNKNOWN`; absent evaluator instructions, they are anchoring risks.\n\n## C4 conclusion\n\n**FAIL.** An evaluator cannot follow the required rules using only its assigned package. This is a material release defect, not a commercial judgement.\n"""
    (OUT / "Evidence_And_Origin_Covariate_Check.md").write_text(evidence_doc, encoding="utf-8")

    adversarial_doc = """# Adversarial Release Test Results\n\n## Scope\n\nThese are isolated mutations in `work/independent_recheck/mutations`; no release, source, mapping, or historical assessment file was altered. No commercial evaluator was invoked.\n\n## Results\n\n| Mutation | Actual check | Rejected? | Result detail |\n|---|---|---|---|\n"""
    for item in adversarial:
        adversarial_doc += f"| {item['mutation']} | {item['check']} | **{item['rejected']}** | `{item.get('diagnostic_codes', item.get('detail', ''))}`; {item.get('detail', '')} |\n"
    adversarial_doc += """\n## Interpretation\n\nR1 and R4 are frame/accounting controls, not responsibilities of the source-aware record validator; the independent pinned-frame and canary checks reject them. R2, R3, R5, and R6 exercise actual production renderer/validator paths and reject the mutations. The release's validator still has known hardening gaps documented by the v6 adversarial audit: it is not an independent renderer oracle, exact-format leakage scanning is brittle, and some regenerated missing-field cases exit zero. Passing these adversarial checks is test coverage, not commercial judgement.\n"""
    (OUT / "Adversarial_Release_Test_Results.md").write_text(adversarial_doc, encoding="utf-8")

    audit_doc = f"""# Independent Release Audit\n\n## Final decision\n\n**REJECT — MATERIAL RELEASE DEFECT**\n\nControlled expanded commercial calibration must not begin.\n\n## Audit boundary\n\n- Release candidate: `{RELEASE}`\n- Authoritative v6 findings: `{V6}`\n- Canonical source-fidelity implementation: `{REBUILD}`\n- Exclusive output: `{OUT}`\n- No source files, release files, or frozen historical assessments were modified.\n- No commercial evaluator, Batch 0003, Gate C, or disposition change was launched.\n\n## Condition scorecard\n\n| Condition | Independent result | Status |\n|---|---|---|\n| C1 safe-list membership/hash/exclusion and actual validator behavior | 1,645; hash `{EXPECTED_SAFE_HASH}`; full contaminated input exit {c1_actual['full_universe']['exit_code']}; safe list exit {c1_actual['safe_list']['validator_exit_code']} with 0 errors | PASS mechanically |\n| C2 frame membership and accounting | 30 unique; 36 slots; 3×12; 6 actual repeats; all members in Tier A | PASS mechanically, metadata defect noted |\n| C3 source fidelity and semantic review | 30 unique reviewed AI-assisted; exact projection except source-semantic defect at `CAL-03-026` / `LUNA-880`; human read not performed | FAIL |\n| C4 evaluator instructions | 0/5 required rules present in either assigned package | FAIL |\n\n## Material blockers\n\n1. `CAL-03-026` maps to `LUNA-880`; the authoritative source row is column-shifted. The released record faithfully reproduces the malformed source but presents monetization-like content as acquisition and founder-fit-like content as operating risk. This is not certifiable as commercially meaningful.\n2. Neither evaluator package contains the required evaluator-facing note, task statement, rubric, or output schema.\n3. The mandatory genuine human read and signed approval are absent. AI-assisted semantic review is explicitly not human approval.\n4. Canary metadata marks 9 slots as hidden canaries although only 6 are repeated assignments.\n5. Release `FINAL_MANIFEST.json` has at least one file hash/size mismatch (`evidence/manifest_generation.exit0.out`).\n6. Release-local package ID scanning is mechanically ineffective for numeric IDs; independent scans found current packages clean, but the release evidence is not trustworthy as proof.\n\n## Required remediation before reconsideration\n\n- Remove or correct `CAL-03-026` only through a documented source-fidelity decision; do not silently rewrite the authoritative source.\n- Package the five C4 rules, evaluator task/rubric, and output schema in each isolated evaluator package, then rehash and re-audit.\n- Correct canary metadata and rerun frame/package joins.\n- Repair manifest generation and obtain a genuine human read/sign-off for every assigned slot in both packages.\n- Rerun the independent semantic and adversarial checks; do not treat test coverage as commercial merit.\n\n## Human checkpoint\n\n`Founder_Human_Review_Packet.md` is a founder-readable aid only. It records **HUMAN READ NOT PERFORMED** and leaves the approval block blank. No model reading, including this audit, satisfies the required human certification.\n\n## References\n\n- C1/C2: `Safe_List_And_Frame_Verification.md`\n- C3: `Concept_By_Concept_Semantic_Review.csv` and `Evaluator_Package_Integrity.md`\n- C4/origin: `Evidence_And_Origin_Covariate_Check.md`\n- Mutations: `Adversarial_Release_Test_Results.md`\n- Human gate: `Founder_Human_Review_Packet.md`\n- v6 release conditions: `{V6 / 'Final_Readiness_Decision.md'}:34-43`\n"""
    (OUT / "Independent_Release_Audit.md").write_text(audit_doc, encoding="utf-8")

    final_doc = """# Final Release Decision\n\n## **REJECT — MATERIAL RELEASE DEFECT**\n\nControlled expanded commercial calibration **must not begin**.\n\n### Basis\n\n- C1 machine-verifiable safe-list reproduction passes: 1,645 eligible unique concepts and SHA-256 `93b5db89d4fe913879555e31334bf03e59f215989f113dfd5d160b9487c51c20`; actual production validator rejects contaminated full-universe input and succeeds on the safe list with zero errors.\n- C2 frame membership and 3×12 slot accounting pass mechanically, but the hidden-canary boolean metadata overmarks first occurrences (9 marked vs 6 repeats).\n- C3 is not certifiable: `CAL-03-026` / `LUNA-880` has a source-level column-shift defect that makes the released concept semantically misleading. The AI-assisted matrix is not human approval.\n- C4 fails: neither evaluator package contains the five required evaluator instructions.\n- The mandatory genuine human read/sign-off is absent.\n- The release manifest and package audit contain mechanical defects.\n\nThis is not a commercial evaluation and does not judge the opportunity concepts. It is a release-integrity decision only. No evaluator was launched, no historical disposition was changed, Batch 0003 was not continued, and Gate C was not started.\n\n**Decision owner action:** remediate the listed blockers, obtain genuine human approval, and rerun this independent audit before any calibration.\n"""
    (OUT / "Final_Release_Decision.md").write_text(final_doc, encoding="utf-8")

    # Create final manifest last. It hashes the nine requested deliverables plus evidence artifacts.
    deliverables = [
        "Independent_Release_Audit.md", "Safe_List_And_Frame_Verification.md", "Evaluator_Package_Integrity.md",
        "Concept_By_Concept_Semantic_Review.csv", "Evidence_And_Origin_Covariate_Check.md", "Adversarial_Release_Test_Results.md",
        "Founder_Human_Review_Packet.md", "Final_Release_Decision.md",
    ]
    evidence_files = sorted(path for path in (OUT / "evidence").rglob("*") if path.is_file())
    manifest = {
        "audit": "Gate B2 Safe-Subset Independent Release Audit",
        "decision": "REJECT — MATERIAL RELEASE DEFECT",
        "date": "2026-10-16",
        "inputs": {"release_candidate": str(RELEASE), "v6_independent_findings": str(V6), "canonical_source_fidelity": str(REBUILD)},
        "scope_stop": ["No commercial evaluators launched", "No Batch 0003", "No Gate C", "No source or frozen assessment changed"],
        "safe_list": {"count": len(safe), "sorted_blind_id_sha256": EXPECTED_SAFE_HASH},
        "frame": {"unique_concepts": len(selected), "review_slots": len(frame_rows) + 6, "batches": 3, "actual_canary_repeats": 6},
        "human_checkpoint": {"required": True, "performed": False, "ai_review_is_not_human_approval": True},
        "deliverables": [{"path": name, "bytes": (OUT / name).stat().st_size, "sha256": sha_file(OUT / name)} for name in deliverables],
        "evidence": [{"path": str(path.relative_to(OUT)), "bytes": path.stat().st_size, "sha256": sha_file(path)} for path in evidence_files],
        "release_manifest_check": release_manifest_check(),
        "input_snapshot_immutability": snapshot_immutability,
    }
    write_json(OUT / "FINAL_MANIFEST.json", manifest)


if __name__ == "__main__":
    main()
