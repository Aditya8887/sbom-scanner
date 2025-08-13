# SBOM Vulnerability Scan using Syft & Grype

This repository includes a GitHub Actions workflow to automatically generate a **Software Bill of Materials (SBOM)** and scan it for known vulnerabilities using **Anchore's Syft** and **Grype**.

## 📌 Features
- **SBOM Generation**: Uses [Syft](https://github.com/anchore/syft) to generate an SBOM from project dependencies.
- **Vulnerability Scanning**: Uses [Grype](https://github.com/anchore/grype) to detect known vulnerabilities from the SBOM.
- **Automated CI/CD Integration**: Runs automatically on pushes and pull requests.
- **Artifact Upload**: Saves scan reports as downloadable artifacts.

## ⚙️ How It Works
1. **Checkout Code** – Retrieves the repository source code.
2. **Install Syft** – For generating the SBOM in JSON format.
3. **Generate SBOM** – Creates `sbom.json` for your project.
4. **Install Grype** – For scanning SBOM for vulnerabilities.
5. **Scan SBOM** – Produces a vulnerability report in table format.
6. **Upload Report** – Stores the report as a GitHub Actions artifact.

## 🚀 Usage
1. Ensure you have a `.github/workflows/sbom-scan.yml` file in your repo:

```yaml
name: SBOM Scan

on:
  push:
    branches:
      - main
  pull_request:

jobs:
  sbom-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install Syft
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Generate SBOM
        run: |
          syft dir:. -o json > sbom.json

      - name: Install Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Scan SBOM with Grype
        run: |
          grype sbom:sbom.json -o table > grype-report.txt

      - name: Upload SBOM report
        uses: actions/upload-artifact@v4
        with:
          name: sbom-report
          path: grype-report.txt
