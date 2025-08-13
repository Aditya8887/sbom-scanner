import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Callable


def generate_sca_report(grype_report: list[dict], baseline: set[str], uid_generator: Callable[[str, str, str, str], str]) -> tuple[list[dict], Counter]:
    '''Generate a Software Composition Analysis (SCA) report from the provided SCA report data.

    Args:
        sca_report (dict): The SCA report containing vulnerability and artifact information.
        baseline (set[str]): A set of baseline vulnerabilities to compare against and skip those.
        uid_generator (Callable): A function to generate a unique identifier for each vulnerability.
    '''
    report = []
    severity_counter = Counter()

    for i in grype_report:
        vuln = i.get('vulnerability', {})
        related_vulns = i.get('relatedVulnerabilities', [])

        artifact = i.get('artifact', {})
        match_details = i.get('matchDetails', [{}])

        searched_by = match_details[0].get('searchedBy', {}).get('package', {})
        found_version = match_details[0].get('found', {}).get('versionConstraint', '')

        name = artifact.get('name') or searched_by.get('name', '')
        version = artifact.get('version') or found_version
        purl = artifact.get('purl', 'undefined')

        primary_vuln = related_vulns[0] if related_vulns else vuln

        cve_id = primary_vuln.get('id', vuln.get('id', 'undefined'))

        # generate UID and skip if in baseline
        uid = uid_generator(name=name, version=version, purl=purl, cve_id=cve_id)
        if uid in baseline:
            continue

        severity = primary_vuln.get('severity', vuln.get('severity', 'undefined'))

        severity_counter[severity] += 1

        data_source = primary_vuln.get('dataSource', vuln.get('dataSource', ''))
        description = primary_vuln.get('description', vuln.get('description', ''))
        risk = primary_vuln.get('risk', vuln.get('risk', 0.0))

        known_exploited = primary_vuln.get('knownExploited') or vuln.get('knownExploited', [])
        cwes = ', '.join({cwe for i in known_exploited for cwe in i.get('cwes', [])})

        cvss_entries = primary_vuln.get('cvss', vuln.get('cvss', []))
        primary_cvss = next((i for i in cvss_entries if i.get('type') == 'Primary' and i.get('version') == '3.1'), {})
        metrics = primary_cvss.get('metrics', {})

        base_score = metrics.get('baseScore', 0.0)
        exploitability_score = metrics.get('exploitabilityScore', 0.0)
        impact_score = metrics.get('impactScore', 0.0)

        fix = primary_vuln.get('fix', vuln.get('fix', {}))
        versions = fix.get('versions', [])
        state = fix.get('state', '')
        fix_version = versions[0] if versions else 'NA'

        report.append({
            'name': name,
            'version': version,
            'purl': purl,
            'cve_id': cve_id,
            'severity': severity,
            'risk': risk,
            'fix_version': fix_version,
            'state': state,
            'description': description,
            'base_score': base_score,
            'exploitability_score': exploitability_score,
            'impact_score': impact_score,
            'cwes': cwes,
            'data_source': data_source
        })

    return report, severity_counter


def uid_generator(name: str, version: str, purl: str, cve_id: str) -> str:
    return f'{name}:{version}:{purl}:{cve_id}'


def load_grype_report(file_path: Path) -> list[dict]:
    if not file_path.exists():
        raise FileNotFoundError(f'Grype report not found: {file_path}')

    with open(file_path) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f'Invalid JSON in grype report {file_path}: {e}')

    if not isinstance(data, dict) or 'matches' not in data:
        raise ValueError(f'Grype report is missing `matches` section: {file_path}')

    return data['matches']


def load_baseline(file_path: Path) -> set[str]:
    if not file_path.exists():
        raise FileNotFoundError(f'Baseline file not found: {file_path}')

    with open(file_path) as f:
        return {line.strip() for line in f if line.strip() and not line.startswith('#')}


def main():
    parser = argparse.ArgumentParser(description='Generate license compliance report.')

    parser.add_argument('-i', '--grype-report', required=True, type=Path, help='SCA report json (grype) file path')
    parser.add_argument('-o', '--output-file', required=True, type=Path, help='Output report path csv')
    parser.add_argument('-b', '--baseline', type=Path, help='Baseline path for comparison')
    parser.add_argument('-p', '--pr-gate', action='store_true', help='Running in PR gate mode')

    args = parser.parse_args()

    args.grype_report = args.grype_report.resolve()
    args.output_file = args.output_file.resolve()

    baseline = set()

    try:
        grype_report = load_grype_report(args.grype_report)
    except Exception as e:
        print(f'Error: {e}')
        return

    if args.baseline:
        args.baseline = args.baseline.resolve()
        try:
            baseline = load_baseline(args.baseline)
        except Exception as e:
            print('Baseline file not found or invalid, defaulting to empty:', e)

    report_data, severity_counter = generate_sca_report(grype_report=grype_report, baseline=baseline, uid_generator=uid_generator)

    if not report_data:
        print('No new vulnerabilities found in the report.')
        return

    with open(args.output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=report_data[0].keys())
        writer.writeheader()
        writer.writerows(report_data)

    print(f'\nTotal vulnerable packages: {len(report_data)}')

    for severity, count in severity_counter.items():
        print(f'  {severity}: {count}')

    sys.exit(0)


if __name__ == '__main__':
    main()
