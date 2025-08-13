import argparse
import subprocess
from pathlib import Path


def run_grype_scan(repo_name: str, sbom_path: Path, report_path: Path):
    try:
        with open(report_path, 'w') as outfile:
            subprocess.run(
                ['grype', f'sbom:{sbom_path}', '-o', 'json'],
                stdout=outfile,
                stderr=None,
                check=True,
            )
        print(
            f'Grype scan completed successfully for repo {repo_name}. Report saved to {report_path}'
        )
    except subprocess.CalledProcessError as e:
        print(f'Error running grype scan: {e.stderr.decode().strip()}')


def main():
    parser = argparse.ArgumentParser(description='Run grype scan on SBOM')

    parser.add_argument('-r', '--repo-name', required=True, type=str, help='Name of the repository')
    parser.add_argument('-s', '--sbom-path', required=True, type=Path, help='Path to the SBOM file')
    parser.add_argument('-o', '--report-dir', required=True, type=Path, help='Directory to save the grype report')

    args = parser.parse_args()

    args.report_dir = args.report_dir.resolve()
    args.report_dir.mkdir(parents=True, exist_ok=True)

    report_path = Path(args.report_dir) / f'{args.repo_name}_grype_report.json'

    run_grype_scan(
        repo_name=args.repo_name,
        sbom_path=args.sbom_path.absolute(),
        report_path=report_path,
    )


if __name__ == '__main__':
    main()
