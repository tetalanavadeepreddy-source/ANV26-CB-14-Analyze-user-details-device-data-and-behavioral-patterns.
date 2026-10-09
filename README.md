# IdentityGuard-X

IdentityGuard-X is a local synthetic-identity risk investigation prototype. It extends the existing FastAPI, SQLAlchemy, SQLite/PostgreSQL-compatible, and React application with supervised classification, anomaly detection, signal fusion, evidence-linked explanations, and investigator feedback.

**This prototype uses synthetic/generated data for training and evaluation. Results should not be interpreted as production fraud-detection accuracy.** No paid APIs or external reputation services are required. IP reputation values in generated scenarios are explicitly simulated test signals.

## Architecture

```text
React + TypeScript investigator UI
	-> FastAPI authenticated API
	-> SQLAlchemy feature queries and event persistence
	-> Random Forest + Isolation Forest + relationship features
	-> configurable weighted risk fusion and evidence confidence
	-> assessments, predictions, observations, feedback in SQLite/PostgreSQL
```

The existing identity directory, profile, behavior, timeline, graph, investigation, Observation Cell, and scenario pages remain in place. The ML artifacts load once when the API module starts; API requests do not train models.

## Technologies

- Frontend: React 19, Vite, TypeScript, Cytoscape.js, Recharts
- Backend: Python 3.10+, FastAPI, Pydantic 2, SQLAlchemy 2, JWT authentication
- Models: scikit-learn `RandomForestClassifier` and `IsolationForest`; both use fixed seeds
- Storage: SQLite by default; `DATABASE_URL` can point to PostgreSQL
- Explainability: measured feature/rule contributions and forest feature importance; SHAP is not used

## Installation and local run

From the repository root in PowerShell:

```powershell
Copy-Item .env.example .env
py -3.10 -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
npm --prefix frontend install
backend\.venv\Scripts\python.exe scripts\train_models.py --samples 6000 --seed 42
```

Start the backend in one terminal:

```powershell
Set-Location backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Start the frontend in another terminal:

```powershell
npm --prefix frontend run dev
```

Open the Vite URL (normally `http://localhost:5173`). Register an account to sign in. To access Observation Cell APIs, register normally and promote a trusted local account to `ANALYST` through database administration; public registration cannot grant staff roles. `scripts/seed_demo.py` also provisions local demo accounts; its shared password is for local testing only.

The repository's `backend/Scripts` environment is workspace-specific. For a fresh checkout, create `backend\.venv` as shown above and use that interpreter for training, testing, and serving.

## Environment variables

Copy `.env.example` to `.env`. SQLite is the default. Set a unique `SECRET_KEY` for local use and never commit `.env`. Risk weights and score thresholds can be changed with the listed `RISK_WEIGHT_*` and `RISK_THRESHOLD_*` variables; weights are normalized at startup. `CORS_ORIGINS` controls allowed frontend origins. Optional PostgreSQL Docker credentials are read from environment variables and have no built-in password.

## Dataset generation and model training

`scripts/train_models.py` creates and saves `ml/data/synthetic_training.csv`, performs a stratified 75/25 train/test split, trains both models, and writes local-only artifacts to `backend/models/`:

- `fraud_model.joblib`: preprocessing pipeline and Random Forest classifier
- `anomaly_model.joblib`: Isolation Forest fitted on legitimate training rows
- `evaluation_metrics.json`: version, feature version, training timestamp, dataset details, and held-out metrics

The default dataset contains 6,000 varied examples across legitimate users/shared Wi-Fi/shared devices/family/office/college networks and suspicious device/identity farms, bot behavior, rapid changes, account bursts, coordinated accounts, suspicious IP activity, abnormal velocity, and synthetic identities. Labels are generated from scenario classes with overlapping signal profiles and 5% label ambiguity; they are not copied from the final risk score. The generated CSV is reproducible with the same seed and is excluded from source control.

Train again:

```powershell
backend\.venv\Scripts\python.exe scripts\train_models.py --samples 6000 --seed 42
```

The current held-out synthetic evaluation (6,000 total, 4,500 train, 1,500 test, seed 42): accuracy 94.53%, precision 94.69%, recall 96.18%, F1 95.43%, ROC-AUC 93.73%; confusion matrix (actual rows, predicted columns) is `[[562, 48], [34, 856]]`. These figures describe this generated dataset only and are not real-world performance estimates. Metrics are exposed at `GET /models/metrics` and shown on the dashboard.

## Features

The model consumes numeric features for account age; exact email, domain, phone, and address reuse; verification; recent identity changes; device age/reuse/count/frequency; IP sharing, VPN/proxy/Tor and simulated reputation; session duration, events/second, action intervals and variance, repeated-action ratio, navigation/login velocity, failed logins; account creation/login bursts; connected users, shared entities, graph degree, cluster size/density, and suspicious neighbors. Exact email reuse is separate from domain reuse; a shared domain alone has only a small capped contribution.

Feature extraction operates on persisted user, event, device, IP, identity-change, and relationship records. Behavior timing is one signal only and does not prove automation. The graph includes users, devices, IPs, and exact email/phone/address identifiers; identifier values are withheld in graph details.

## Risk scoring and explanations

The default normalized weights are identity 20%, device 15%, network 10%, behavior 15%, temporal 10%, graph 10%, supervised ML 15%, and anomaly 5%. A bounded corroboration bonus applies only when multiple independent signal groups are elevated; its threshold, per-signal bonus, and cap are configurable. Score bands are LOW 0–29, MEDIUM 30–59, HIGH 60–79, CRITICAL 80–100. Decisions are ALLOW, MONITOR, REVIEW, and ESCALATE respectively. High/critical predictions with low evidence confidence are downgraded to REVIEW. Scores never permanently block accounts.

Risk score and evidence confidence are separate. Confidence is a coverage proxy based on observed events, linked entities, and identity changes, not a calibrated probability. Explanations include measured feature values and weighted contributions, plus mitigating shared-infrastructure context where accounts are mature, verified, and behave normally. The ML probability and Isolation Forest anomaly contribution are distinct outputs.

## API endpoints

- `POST /risk/analyze`: validated user/session/device/IP/event analysis request; identifiers are hashed before persistence
- `POST /users/{user_id}/analyze`: existing profile scan, now routed through the same model/fusion service
- `GET /users/{user_id}/risk`, `/features`, `/timeline`, `/graph`, `/indicators`
- `GET /models/metrics`: synthetic holdout metrics and forest feature importance
- `POST /risk/predictions/{prediction_id}/feedback`: store `CONFIRM_FRAUD` or `FALSE_POSITIVE` and the prediction feature snapshot
- Existing `/auth/*`, `/events`, `/dashboard/*`, `/observations`, `/investigations`, and `/demo/scenarios/*` routes remain

Interactive API documentation is available at `http://127.0.0.1:8000/docs` after backend startup. `/risk/analyze` requires an existing authenticated user's `user_id`; incoming event names, timestamps, duration, IP, device/session lengths, and event counts are validated.

## Scenarios

Open **Demo scenarios** in the app. Each click writes scenario users, events, devices, and network links to the active database, then submits every created user to the real backend analysis route. The page shows returned scores and decisions and links to each profile. Supported scenarios include normal user, shared Wi-Fi, shared device, identity farm, device farm, bot behavior, rapid identity changes, coordinated accounts, and account creation burst. Scenario records start unscored; no output score is preloaded.

## Investigator feedback and retraining

Feedback is persisted but never triggers automatic training. Export numeric snapshots and deliberately train a new model offline:

```powershell
backend\.venv\Scripts\python.exe scripts\export_feedback.py
backend\.venv\Scripts\python.exe scripts\train_models.py --samples 6000 --seed 42 --feedback-csv ml\data\investigator_feedback.csv
```

Review exported labels and dataset composition before using feedback; synthetic and investigator-labeled examples may be biased or sparse.

## Testing

```powershell
backend\.venv\Scripts\python.exe -m pytest backend\tests -q
npm --prefix frontend run build
npm --prefix frontend run lint
```

Tests cover feature extraction, exact-email versus domain reuse, model persistence/inference, API validation, identifier hashing, feedback storage, decision thresholds, graph behavior, observation lifecycle, and real end-to-end scenario scoring.

## Limitations and future work

- Synthetic/test performance does not establish production accuracy; real labeled, representative data and calibration are required.
- Reputation flags are generated/test values, not live intelligence. No geolocation, paid API, or external data enrichment is performed.
- The Random Forest is used instead of XGBoost to keep the local dependency stack reliable; SHAP is not installed. Explanations are transparent signal/feature contributions, not SHAP values.
- Evidence confidence is a simple completeness proxy and needs calibration before operational use.
- The prototype is not a production fraud-control system: add migrations, deployment secrets management, rate limits, privacy review, monitoring, and adversarial evaluation before deployment.
