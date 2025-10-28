# Serverless Secret Scanner for Public Code Repositories (GCP)

## TL;DR 📄
This project implements an automated pipeline on Google Cloud Platform (GCP) to scan public code repositories (via the BigQuery GitHub dataset) for potential leaked secrets. It uses a Cloud Function (running on Cloud Run - 2nd Gen) triggered by Cloud Scheduler, queries BigQuery, analyzes findings with the Vertex AI Gemini API, and logs confirmed leaks back to a BigQuery table.

This demonstrates skills relevant to an AI-Powered SecOps Analyst role, including automation, cloud security, large-scale data analysis (threat hunting), and AI integration for alert enrichment/filtering.

---

## Project Goal 🎯
To build a serverless, automated system for identifying potentially exposed credentials in public code, leveraging cloud-native GCP services and AI for efficient analysis and filtering of false positives.

---

## Architecture Flow ⚙️
**Cloud Scheduler** (Daily Trigger `0 8 * * *`) -> **Cloud Function/Run HTTP URL** (GET Request) -> **Python Function Execution** -> **BigQuery Query** (`bigquery-public-data.github_repos`) -> **Vertex AI Gemini API** (Analyze potential secrets) -> **BigQuery Insert** (`secops-secret-scanner.secret_scanner_results.confirmed_leaks`)

---

## Key GCP Components Used 🛠️
* **Project:** `secops-secret-scanner`
* **Cloud Run / Cloud Functions (2nd Gen):** `secret-scanner-function` (Python 3.13) - Hosts the core scanning and analysis logic. Triggered via HTTP URL.
* **BigQuery:**
    * Public Dataset Queried: `bigquery-public-data.github_repos` (specifically `files` and `contents` tables).
    * Results Dataset: `secret_scanner_results`
    * Results Table: `confirmed_leaks`
* **Vertex AI:** `gemini-1.5-flash-001` - Used via API for AI-driven analysis of potential secrets.
* **Cloud Scheduler:** `daily-secret-scan-trigger` - Provides the daily cron-like trigger.
* **IAM:** Appropriate roles (`BigQuery Job User`, `Vertex AI User`, `BigQuery Data Editor`) granted to the function's service account (`Default compute service account`).
* **Cloud Build:** Used behind the scenes by Cloud Run/Functions to build the container image.
* **APIs Enabled:** Cloud Run, BigQuery, Vertex AI, Cloud Scheduler, IAM, Cloud Build, etc.

---

* **SQL Query:** The core BigQuery hunt query is defined within `main.py` and is also available for easier viewing in `hunt_query.sql`.

## Setup & Deployment Summary 🚀
1.  **GCP Project Setup:** Created project `secops-secret-scanner`, enabled necessary APIs.
2.  **BigQuery Setup:** Created dataset `secret_scanner_results` and table `confirmed_leaks`.
3.  **Cloud Function Deployment:** Deployed Python code (`main.py`, `requirements.txt`) via the Cloud Run "inline function editor" (2nd Gen function), configured HTTP trigger (Allow unauthenticated), assigned appropriate service account roles. Increased memory/timeout as needed.
4.  **BigQuery Query Development:** Developed and refined SQL query with regex (`REGEXP_EXTRACT`, `REGEXP_CONTAINS`) in BigQuery UI to identify potential secrets. Iteratively fixed syntax errors based on Job History.
5.  **Cloud Scheduler Setup:** Created a job to trigger the function's HTTP URL daily.

---

## Screenshots 📸

**1. Enabled APIs:**
Shows the key APIs like BigQuery, Vertex AI, Cloud Run, Cloud Scheduler enabled in the project.

![Enabled APIs Part 1](Screenshot%20(135).png)
![Enabled APIs Part 2](Screenshot%20(136).png)

**2. BigQuery Hunt Query & Initial Test Results:**
Demonstrates the working SQL query in the BigQuery UI finding potential secrets (before Cloud Function implementation).

![BigQuery Hunt Query Test](Screenshot%20(140).png)

**3. Cloud Function Logs - Successful Run:**
Shows the logs from a successful test execution of the deployed Cloud Function, indicating the query ran and processed candidates.

![Cloud Function Success Log](Screenshot%20(161).png)

**4. Final Results Table Query:**
Shows the query against the `confirmed_leaks` table in BigQuery, confirming the table exists and the pipeline's end state (even if no leaks were logged in the test run shown).

![Final Results Table Query](Screenshot%20(162).png)

**5. Cloud Scheduler Job:**
Shows the configured Cloud Scheduler job set to trigger the function daily.

![Cloud Scheduler Job](Screenshot%20(163).png)
