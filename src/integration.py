import os
import json
import subprocess
import requests
import tempfile
import click


from itertools import groupby
from abc import ABC, abstractmethod
from dotenv import load_dotenv
load_dotenv()

FEEDBACK_HANDLER = os.environ.get("FEEDBACK_HANDLER", "http://safeliner.tech/feedback")
DFG_BUILDER_PATH = os.environ.get("DFG_BUILDER_PATH", "dfg-builder-cli")
ANALYZE_HANDLER = os.environ.get("ANALYZE_HANDLER", "http://safeliner.tech/analyze")
BEARER_TOKEN = os.environ.get("BEARER_TOKEN")

class SastScanner(ABC):

    @abstractmethod
    def scan(self, file_path, file_data):
        pass


class SemgrepScanner(SastScanner):

    def __init__(self, config_path):
        self.config_path = config_path

    def scan(self, file_path: str, file_data: str) -> list:
        with tempfile.NamedTemporaryFile(suffix="." + file_path.split(".")[-1]) as fp:
            fp.write(file_data.encode())
            fp.flush()
            if self.config_path == "":
                out = subprocess.check_output(["semgrep", "--sarif", "-q", fp.name])
            else:
                out = subprocess.check_output(
                    ["semgrep", "--config", self.config_path, "--sarif", "-q", fp.name]
                )
            scan_report = json.loads(out)["runs"][0]["results"]

            for i in range(len(scan_report)):
                scan_report[i]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = file_path

            return scan_report


class FixChecker:

    def __init__(self, scanner: SemgrepScanner, finding, file_data: str):
        self.scanner = scanner
        self.finding = finding
        self.file_path = finding["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        results = self.scanner.scan(self.file_path, file_data)
        self.original_findings = len(
            [f for f in results if self._normalize_rule_id(f["ruleId"]) == self._normalize_rule_id(finding["ruleId"])]
        )

    def _normalize_rule_id(self, rule_id: str) -> str:
        """Убирает из имени правила префиксы, которые являются частью пути до файла с правилом. Необходимо в случае, если sarif был получен извне, а не локально."""
        langs = {"stabs": {}, "bash": {}, "c": {}, "csharp": {}, "cpp": {}, "clojure": {}, "dockerfile": {}, "generic": {}, "go": {}, "html": {}, "json": {}, "java": {}, "javascript": {}, "kotlin": {}, "lua": {}, "ocaml": {}, "php": {}, "python": {}, "ruby": {}, "rust": {}, "scala": {}, "solidity": {}, "swift": {}, "terraform": {}, "typescript": {}, "xml": {}, "yaml": {}}
        parts = rule_id.split(".")
        s = 0
        for i, part in enumerate(parts):
            for lang in langs:
                if part == lang:
                    s = i
                    break
            else:
                continue
            break
        if parts[-1] == parts[-2]:
            return ".".join(parts[s:-1])
        return ".".join(parts[s:])
    
    def check_fix(self, applied_fix: str) -> bool:
        results = self.scanner.scan(self.file_path, applied_fix)
        new_findings = len(
            [f for f in results if  self._normalize_rule_id(f["ruleId"]) ==  self._normalize_rule_id(self.finding["ruleId"])]
        )
        return new_findings < self.original_findings


def get_finding_snippet(finding) -> str:
    return finding["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]

def get_finding_cwe_id(finding, report) -> list[str]:
    result = []
    for rule in report["runs"][0]["tool"]["driver"]["rules"]:
        if rule["id"] == finding["ruleId"]:
            for tag in rule["properties"]["tags"]:
                if "CWE" in tag:
                    result.append(tag.split(":")[0])
    return result

def send_feedback(
    request_id: str,
    fix_sast_passed: bool = None,
    false_positive_confirmed: bool = None,
    fix_human_passed: bool = None,
    finding_resolved: bool = None,
):
    feedback = {"request_id": request_id}

    if fix_sast_passed is not None:
        feedback["fix_sast_passed"] = fix_sast_passed
    if false_positive_confirmed is not None:
        feedback["false_positive_confirmed"] = false_positive_confirmed
    if fix_human_passed is not None:
        feedback["fix_human_passed"] = fix_human_passed
    if finding_resolved is not None:
        feedback["finding_resolved"] = finding_resolved

    resp = requests.post(
        FEEDBACK_HANDLER,
        json=feedback,
        headers={"Authorization": f"Bearer {BEARER_TOKEN}"},
    )
    if resp.status_code != 200:
        print(f"Failed to send feedback: {resp.status_code}")


def perform_finding_analysis(finding, semgrep_config: str,cwe_ids: list[str], fix_attempts: int, feedback: bool):
    file_path = finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    file_data = open(file_path, "r").read()
    result = {}

    scanner = SemgrepScanner(semgrep_config)
    fix_checker = FixChecker(scanner, finding, file_data)

    req = {
        "finding": {
            "description": finding["message"]["text"],
            "rule": finding["ruleId"],
            "tool": "semgrep",
            "cwe_ids": cwe_ids,
            "location": {
                "file_path": file_path,
                "start_row": finding["locations"][0]["physicalLocation"]["region"]["startLine"],
                "start_col": finding["locations"][0]["physicalLocation"]["region"]["startColumn"],
                "end_row": finding["locations"][0]["physicalLocation"]["region"]["endLine"],
                "end_col": finding["locations"][0]["physicalLocation"]["region"]["endColumn"],
            },
        },
        "files": {file_path: file_data},
    }

    resp = requests.post(
        ANALYZE_HANDLER,
        json=req,
        headers={"Authorization": f"Bearer {BEARER_TOKEN}"},
    )

    if resp.status_code != 200:
        result["error"] = f"Error: {resp.status_code}, body: {resp.text}"
        return result

    resp = resp.json()
    req["request_id"] = resp["request_id"]

    if "require_context" in resp:
        start_line = finding["locations"][0]["physicalLocation"]["region"]["startLine"]
        try:
            dfgInfo = subprocess.check_output(
                [DFG_BUILDER_PATH, "in", ".", f"{file_path}:{start_line}"]
            )
            all_file_names = [x["file_name"] for x in json.loads(dfgInfo)["snippets"]]
            for file_name in all_file_names:
                req["files"][file_name] = open(file_name, "r").read()
            req["context"] = {"dfg": dfgInfo.decode()}
            resp = requests.post(
                ANALYZE_HANDLER,
                json=req,
                headers={f"Authorization": f"Bearer {BEARER_TOKEN}"},
            )
        except subprocess.CalledProcessError as e:
            result["cli-error"] = f"Error dfg-cli: {e.returncode}, body: {e.output}"
            req["options"] = {"force_ignore_dfg": True}
            resp = requests.post(
                ANALYZE_HANDLER,
                json=req,
                headers={f"Authorization": f"Bearer {BEARER_TOKEN}"},
            )
        if resp.status_code != 200:
            result["error"] = f"Error: {resp.status_code}, body: {resp.text}"
            return result

        resp = resp.json()

    if "is_false_positive" in resp and resp["is_false_positive"]:
        result["is_false_positive"] = True
        result["explanation"] = resp["explanation"]
        return result
    elif "is_false_positive" in resp:
        result["is_false_positive"] = False

    result["explanation"] = resp["explanation"]

    req["history"] = []
    if "options" not in req:
        req["options"] = {}
    req["options"]["do_triage"] = False
    req["options"]["do_explain"] = False
    result["fix_history"] = []
    result["fixed"] = False
    for i in range(fix_attempts):
        fixed_files = resp["fixed_files"]
        fixedFile = fixed_files[
            finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        ]
        result["fix_history"].append(fixed_files)
        if fix_checker.check_fix(fixedFile):
            result["fixed"] = True
            if feedback:
                send_feedback(resp["request_id"], fix_sast_passed=True)
            break
        elif i != fix_attempts - 1:
            req["history"].append(resp["raw_fix"])
            resp = requests.post(
                ANALYZE_HANDLER,
                json=req,
                headers={"Authorization": f"Bearer {BEARER_TOKEN}"},
            )
            if resp.status_code != 200:
                result["error"] = f"Error: {resp.status_code}, body: {resp.text}"
                return result
            resp = resp.json()

    return result


def perform_file_analysis(
    semgrep_config: str,
    file_path: str,
    findings: list,
    report: dict,
    fix_attempts: int = 2,
    feedback: bool = True,
):
    print(f"Checking file {file_path}")
    scanner = SemgrepScanner(semgrep_config)
    # check if rescan needed
    res = subprocess.run(
        ["git", "diff", "--exit-code", file_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if res.returncode:
        findings = scanner.scan(file_path, open(file_path, "r").read())
    fp_or_unfixed = set()
    for i in range(len(findings)):
        need_rescan = False
        for finding in findings:
            snippet = get_finding_snippet(finding)
            cwe_ids = get_finding_cwe_id(finding, report)
            if snippet in fp_or_unfixed:
                continue

            result = perform_finding_analysis(finding, semgrep_config, cwe_ids, fix_attempts, feedback)
            if "error" in result:
                err = result["error"]
                print(f"Error: {err}")
                continue
            if "is_false_positive" in result and result["is_false_positive"]:
                print(f"Finding {snippet} in file {file_path} is false positive, skipping")
                print(result["explanation"])
                fp_or_unfixed.add(snippet)
                continue
            elif not result["fixed"]:
                print(f"Finding {snippet} in file {file_path} can not be fixed, skipping")
                fp_or_unfixed.add(snippet)
                continue
            else:
                print(result["explanation"])
                print(f"Finding {snippet} in file {file_path} is fixed")
                for file_path, file_data in result["fix_history"][-1].items():
                    with open(file_path, "w") as fp:
                        fp.write(file_data)
                need_rescan = True
                break
        if need_rescan:
            findings = scanner.scan(file_path, open(file_path, "r").read())
        else:
            break

@click.group()
def cli():
    pass

@click.command()
@click.argument('sarif_path')
@click.option('--semgrep-config', type=str, default="", help="Path to semgrep rullpack.")
@click.option('--feedback/--no-feedback', default=True, help="Report feedback.")
def apply_report(sarif_path: str, semgrep_config: str, feedback: bool):
    report = json.load(open(sarif_path))

    for file_path, findings in groupby(
        report["runs"][0]["results"],
        lambda x: x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
    ):
        if not file_path.startswith("."):
            perform_file_analysis(semgrep_config, file_path, list(findings), report, feedback=feedback)
        
@click.command()
@click.argument('sarif_path')
@click.option('--semgrep-config', type=str, default="", help="Path to semgrep rullpack.")
@click.option('--feedback/--no-feedback', default=False, help="Report feedback.")
@click.option('-o', "--output", type=str, default="", help="Path to semgrep rullpack.")
def get_report(sarif_path: str, semgrep_config: str, feedback: bool, output: str):
    report = json.load(open(sarif_path))

    results = []
    for finding in report["runs"][0]["results"]:
        cwe_ids = get_finding_cwe_id(finding, report)
        results.append(perform_finding_analysis(finding, semgrep_config, cwe_ids, 2, feedback=feedback))

    if output != "":
        with open(output, "w") as f:
            json.dump(results, f)
    else:
        print(json.dumps(results))

if __name__ == "__main__":
    cli.add_command(apply_report)
    cli.add_command(get_report)
    cli()
