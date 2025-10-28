import functions_framework
import google.cloud.bigquery as bq
import vertexai
from vertexai.generative_models import GenerativeModel, Part
from datetime import datetime
import re # Import the regex module
import logging # Import logging
import google.api_core.exceptions # Import exceptions

# Configure logging
logging.basicConfig(level=logging.INFO)

# --- CONFIGURATION ---
PROJECT_ID = "secops-secret-scanner"  # Your GCP Project ID
DATASET_ID = "secret_scanner_results" # Just the Dataset Name
TABLE_ID = "confirmed_leaks"        # The table name
LOCATION = "us-central1" # Or your BQ/Vertex region

# Initialize clients only once globally to optimize function cold starts
try:
    vertexai.init(project=PROJECT_ID, location=LOCATION)
    bq_client = bq.Client(project=PROJECT_ID)
    gen_model = GenerativeModel("gemini-1.5-flash-001")
    logging.info("Vertex AI and BigQuery clients initialized successfully.")
except Exception as e:
    logging.error(f"Error initializing clients: {e}", exc_info=True)
    raise

# The BigQuery hunt query (NO raw strings, using DOUBLE BACKSLASHES for escapes)
HUNT_QUERY = """
    SELECT
      f.repo_name,
      f.path,
      c.content,
      -- REGEXP_EXTRACT without r'' and using \\ for escapes, including \'
      REGEXP_EXTRACT(c.content, '(?i)(?:api_key|secret_key|access_token)\\\\s*[:=]\\\\s*["\\\']?([-a-zA-Z0-9_./]{20,})["\\\']?') AS potential_secret
    FROM
      `bigquery-public-data.github_repos.files` AS f
    JOIN
      `bigquery-public-data.github_repos.contents` AS c
    ON
      f.id = c.id
    WHERE
      -- REGEXP_CONTAINS without r'' and using \\.
      (REGEXP_CONTAINS(f.path, '\\\\.(py|ya?ml|json|env|conf|cfg|properties|sh)$') OR f.path LIKE '%config%')
      AND c.size < 100000 -- Avoid huge files
      -- REGEXP_CONTAINS without r'' and using \\s
      AND REGEXP_CONTAINS(c.content, '(?i)(api_key|secret|token|password|credential|private_key)\\\\s*[:=]')
      -- REGEXP_CONTAINS without r'' - no escapes needed here
      AND NOT REGEXP_CONTAINS(f.path, '(?i)(test|example|sample|demo|mock|fake)')
      AND c.content IS NOT NULL -- Ensure content is not null
      AND LENGTH(c.content) > 0 -- Ensure content is not empty
    LIMIT 25; -- Limit results for function runtime constraints
"""

def analyze_with_ai(code_snippet, potential_secret_value):
    """Use Vertex AI Gemini to analyze a code snippet for a real secret."""

    # Basic check for obviously fake keys before calling AI
    if potential_secret_value is None or "example" in potential_secret_value.lower() or "test" in potential_secret_value.lower() or potential_secret_value.startswith("YOUR_") or potential_secret_value.endswith("_HERE"):
         logging.info(f"Skipping AI analysis for likely placeholder: {potential_secret_value}")
         return "CONFIDENCE: None\nREASONING: Likely placeholder or example value."

    # Provide context around the potential secret
    context_window = 150 # Characters before and after
    contextual_snippet = potential_secret_value
    if code_snippet and potential_secret_value:
        try:
            matches = list(re.finditer(re.escape(potential_secret_value), code_snippet))
            if matches:
                match_start = matches[0].start()
                match_end = matches[0].end()
                start = max(0, match_start - context_window)
                end = min(len(code_snippet), match_end + context_window)
                contextual_snippet = code_snippet[start:end]
                if start > 0: contextual_snippet = "..." + contextual_snippet
                if end < len(code_snippet): contextual_snippet = contextual_snippet + "..."
            else:
                 contextual_snippet = code_snippet[:context_window*2] + "..." # Provide beginning if not found
        except Exception as e:
            logging.warning(f"Error extracting context for secret value: {e}. Using value only.")
            contextual_snippet = potential_secret_value # Fallback

    prompt = f"""
    You are a Senior Security Analyst specializing in Data Loss Prevention (DLP) reviewing code snippets for leaked secrets.
    Analyze the following 'Potential Secret Value' found within the 'Code Snippet Context'.
    Determine if the value looks like a REAL, ACTIVE credential (API key, token, password) or if it's likely a FALSE POSITIVE (placeholder, example, test data, deactivated key format, identifier, configuration value).

    Consider factors like:
    - Key patterns (common prefixes like sk_live_, AKIA, etc.)
    - Entropy/Randomness of the string
    - Surrounding code (variable names like 'api_key', 'password'; comments mentioning 'test' or 'example')
    - Common placeholder formats (e.g., 'YOUR_API_KEY_HERE', 'xxxxxxxx')

    Provide your analysis STRICTLY in this format:
    CONFIDENCE: [High | Medium | Low | None]
    REASONING: [Your brief explanation justifying the confidence level. Be concise.]

    **Code Snippet Context:**
    ```
    {contextual_snippet}
    ```

    **Potential Secret Value:**
    {potential_secret_value}

    **Your Analysis:**
    """

    try:
        response = gen_model.generate_content(prompt, stream=False)
        # Handle potential API response variations
        analysis_text = ""
        if response and response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
             analysis_text = response.candidates[0].content.parts[0].text
        else:
             analysis_text = response.text if hasattr(response, 'text') else str(response) # Fallback

        if "CONFIDENCE:" not in analysis_text or "REASONING:" not in analysis_text:
            logging.warning(f"AI response format invalid: {analysis_text}")
            return "CONFIDENCE: Low\nREASONING: AI response format error."
        return analysis_text
    except Exception as e:
        logging.error(f"Error communicating with Vertex AI: {e}", exc_info=True)
        if "Quota" in str(e):
             return "CONFIDENCE: None\nREASONING: Vertex AI quota exceeded during analysis."
        return "CONFIDENCE: None\nREASONING: Error during AI analysis communication."


def log_to_bigquery(rows_to_insert):
    """Insert confirmed leaks into our results table."""
    if not rows_to_insert:
        logging.info("No new high/medium confidence leaks to insert into BigQuery.")
        return

    try:
        table_ref = bq_client.dataset(DATASET_ID).table(TABLE_ID)
        errors = bq_client.insert_rows_json(table_ref, rows_to_insert)
        if not errors:
            logging.info(f"Successfully inserted {len(rows_to_insert)} rows into BigQuery table {DATASET_ID}.{TABLE_ID}.")
        else:
            for error_detail in errors:
                 logging.error(f"BigQuery insert error: Index {error_detail['index']}, Errors: {error_detail['errors']}")
    except Exception as e:
        logging.error(f"Failed to insert rows into BigQuery: {e}", exc_info=True)


# Main function triggered by HTTP
@functions_framework.http
def hunt_and_analyze(request):
    """Main Cloud Function entry point."""
    logging.info("Cloud Function execution started.")
    rows_to_insert = [] # Initialize list for BQ insertion

    try:
        logging.info("Starting BigQuery hunt query...")
        query_job = bq_client.query(HUNT_QUERY)
        results = query_job.result() # Wait for job completion
        logging.info(f"BigQuery hunt query complete. Found {results.total_rows} potential candidates.")

        count = 0
        processed_count = 0
        for row in results:
            processed_count += 1
            potential_secret_value = getattr(row, 'potential_secret', None)
            repo_name = getattr(row, 'repo_name', 'N/A')
            file_path = getattr(row, 'path', 'N/A')

            if not potential_secret_value or not isinstance(potential_secret_value, str):
                logging.debug(f"Row {processed_count}: No valid potential_secret found for {repo_name}/{file_path}. Skipping.")
                continue

            content_value = getattr(row, 'content', None)
            if not content_value or not isinstance(content_value, str):
                 logging.warning(f"Row {processed_count}: Content missing for {repo_name}/{file_path}. Using only secret value for AI context.")
                 content_value = ""

            logging.info(f"Row {processed_count}: Analyzing potential secret in: {repo_name}/{file_path}")
            ai_analysis = analyze_with_ai(content_value, potential_secret_value)
            logging.debug(f"Row {processed_count}: AI Analysis result:\n{ai_analysis}")

            confidence = "None"
            reasoning = "Parsing error"
            try:
                lines = ai_analysis.strip().split('\n')
                if len(lines) >= 1 and lines[0].startswith("CONFIDENCE:"):
                    confidence = lines[0].split(":", 1)[1].strip()
                if len(lines) >= 2 and lines[1].startswith("REASONING:"):
                    reasoning = lines[1].split(":", 1)[1].strip()
                elif len(lines) == 1:
                     reasoning = "AI response missing reasoning."

            except Exception as e:
                logging.warning(f"Error parsing AI response: {e}. Raw: {ai_analysis}")
                reasoning = f"Parsing error: {e}"

            logging.info(f"Row {processed_count}: AI Confidence: {confidence} for {repo_name}/{file_path}")

            if confidence.lower() in ["high", "medium"]:
                count += 1
                new_row = {
                    "repo_name": repo_name,
                    "file_path": file_path,
                    "secret_snippet": potential_secret_value[:1024],
                    "ai_confidence": confidence,
                    "ai_reasoning": reasoning[:1024],
                    "scan_timestamp": datetime.utcnow().isoformat(timespec='microseconds') + "Z"
                }
                rows_to_insert.append(new_row)
                logging.info(f"Row {processed_count}: Added potential leak #{count} from {repo_name}/{file_path} for BQ insertion.")

        log_to_bigquery(rows_to_insert)

        final_message = f"Scan complete. Processed {processed_count} candidates. Found and logged {len(rows_to_insert)} high/medium-confidence leaks."
        logging.info(final_message)
        return final_message, 200 # HTTP OK

    except google.api_core.exceptions.Forbidden as e:
         logging.error(f"Permission error during BigQuery job execution: {e}", exc_info=True)
         return f"Permission Error: {e}", 500
    except google.api_core.exceptions.BadRequest as e:
         logging.error(f"Bad Request/Query Syntax error during BigQuery job execution: {e}", exc_info=True)
         # Log the exact query that failed for easier debugging
         logging.error(f"Failing Query:\n---\n{HUNT_QUERY}\n---")
         return f"Bad Query Error: {e}", 500
    except Exception as e:
        logging.error(f"Critical error during function execution: {e}", exc_info=True)
        return f"Error during execution: {e}", 500 # HTTP Server Error
