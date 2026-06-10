# CST8919 Lab 2: Web App Threat Detection with Azure Monitor and KQL

A Flask login demo app that logs authentication attempts to stdout for Azure Monitor diagnostic logging, KQL analysis, and brute-force alert rules.

## Demo Video

**YouTube:** [Add your 5-minute demo link here](https://youtube.com)

## What I Learned

- How Azure App Service console logs flow into a Log Analytics workspace via diagnostic settings.
- How to write KQL queries against `AppServiceConsoleLogs` to detect failed login patterns.
- How to configure Azure Monitor alert rules with aggregation, thresholds, and email action groups.

## Challenges

- Log propagation delay: console logs can take a few minutes to appear in Log Analytics after diagnostic settings are enabled.
- Matching log text reliably in KQL required consistent, structured log messages from the application.

## Real-World Improvements

- Use structured JSON logging and Application Insights instead of parsing free-text console output.
- Track failed attempts per IP/username with rate limiting and account lockout.
- Correlate with WAF logs, geo-IP, and known credential-stuffing indicators.
- Add SIEM integration, runbooks, and automated response (block IP, disable account).

---

## Project Structure

```
.
├── app.py              # Flask app with /login route
├── requirements.txt    # Python dependencies
├── test-app.http       # REST Client tests (VS Code)
├── startup.txt         # Azure App Service startup command
└── README.md
```

## Local Development

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Test with the REST Client extension in VS Code using `test-app.http`.

**Default credentials:** `admin` / `secret123` (override with `VALID_USERNAME` and `VALID_PASSWORD` env vars).

---

## Azure Deployment

### 1. Create resources

1. **Log Analytics Workspace** (same region as the web app).
2. **App Service** (Python 3.12, Linux recommended).

### 2. Deploy the app

**Option A – GitHub deployment**

1. Push this repo to GitHub.
2. In App Service → Deployment Center, connect the repository.
3. Set **Startup Command** (Configuration → General settings):

   ```
   gunicorn --bind=0.0.0.0:8000 --timeout 600 app:app
   ```

**Option B – Azure CLI**

```bash
az webapp up --name YOUR-APP-NAME --resource-group YOUR-RG --runtime "PYTHON:3.12"
az webapp config set --name YOUR-APP-NAME --resource-group YOUR-RG \
  --startup-file "gunicorn --bind=0.0.0.0:8000 --timeout 600 app:app"
```

### 3. Enable diagnostic logging

App Service → **Monitoring → Diagnostic settings** → Add diagnostic setting:

| Log type | Purpose |
|----------|---------|
| `AppServiceConsoleLogs` | **Required** – captures login attempt logs |
| `AppServiceHTTPLogs` | Optional – HTTP request metadata |

Send logs to your Log Analytics workspace.

### 4. Generate test traffic

Update `@host` in `test-app.http`, then send multiple failed `/login` requests (6+ within 5 minutes) to simulate brute-force activity.

---

## KQL Queries

### Failed login attempts (exploration)

```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(1h)
| where ResultDescription contains "LOGIN_FAILED"
| project TimeGenerated, ResultDescription
| order by TimeGenerated desc
```

**Explanation:** Filters console logs to failed login lines. `LOGIN_FAILED` is emitted by the app for invalid credentials.

### Brute-force detection (alert rule query)

```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(5m)
| where ResultDescription contains "LOGIN_FAILED"
| summarize FailedLoginCount = count()
```

**Explanation:** Counts failed logins in the last 5 minutes. Use this as the alert condition with **Table rows > 5**, **Aggregation granularity: 5 minutes**, **Evaluation frequency: 1 minute**.

### Per-username breakdown (optional)

```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(1h)
| where ResultDescription contains "LOGIN_FAILED"
| extend Username = extract(@"username=([^\s]+)", 1, ResultDescription)
| summarize FailedAttempts = count() by Username
| order by FailedAttempts desc
```

---

## Alert Rule Configuration

| Setting | Value |
|---------|-------|
| Scope | Your Log Analytics workspace |
| Condition | Brute-force KQL query above |
| Measure | Table rows |
| Threshold | Greater than 5 |
| Aggregation granularity | 5 minutes |
| Evaluation frequency | 1 minute |
| Severity | 2 or 3 |
| Action | Action group with email notification |

---

## Log Format

The app writes structured messages to stdout:

```
LOGIN_FAILED timestamp=2025-06-10T12:00:00+00:00 username=hacker ip=127.0.0.1
LOGIN_SUCCESS timestamp=2025-06-10T12:01:00+00:00 username=admin ip=127.0.0.1
```

Azure captures these in `AppServiceConsoleLogs.ResultDescription`.
