import json
from pathlib import Path

from .catalog import DEFENDER_OBSERVED_DETECTIONS


def av_report(test_cases):
    files = []
    observed = 0
    for test_case in test_cases:
        status = "defender-observed" if test_case.key in DEFENDER_OBSERVED_DETECTIONS else "not-observed"
        if status == "defender-observed":
            observed += 1
        files.append(
            {
                "key": str(test_case.key),
                "filename": test_case.filename,
                "status": status,
                "description": test_case.description,
            }
        )
    return {
        "summary": {
            "total": len(test_cases),
            "defender_observed": observed,
            "not_observed": len(test_cases) - observed,
        },
        "files": files,
    }


def print_av_report(test_cases):
    report = av_report(test_cases)
    for file_entry in report["files"]:
        print(f"{file_entry['filename']}\t{file_entry['status']}\t{file_entry['description']}")
    summary = report["summary"]
    print(
        f"SUMMARY\ttotal={summary['total']}"
        f"\tdefender_observed={summary['defender_observed']}"
        f"\tnot_observed={summary['not_observed']}"
    )


def write_av_report_json(test_cases, report_path):
    report = av_report(test_cases)
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = report["summary"]
    print(
        f"Wrote AV report JSON: {path} "
        f"(total={summary['total']}, "
        f"defender_observed={summary['defender_observed']}, "
        f"not_observed={summary['not_observed']})"
    )
