-- File: hunt_query.sql
-- Description: BigQuery SQL query used by the Cloud Function to find potential secrets.

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
    LIMIT 25; -- Limit results for function runtime constraints  -- Note: Limit is applied in Python code, shown here for context
