# AI-Powered CyberShield

An integrated website security assessment platform built as a BTech CSE minor project — five detection modules (password strength, SSL/TLS, HTTP security headers, passive website reconnaissance, ML-based phishing detection) unified by a weighted AI Risk Score, plus a hybrid rule-engine + local-LLM Security Advisor that turns raw findings into prioritized, natural-language recommendations.

An accompanying research paper documents the system's design, three dataset-bias findings discovered and fixed during development, and a comparative evaluation of three ML classifiers.

## Repo structure

```
cybershield/     — the application (FastAPI + Jinja2 + SQLite/PostgreSQL)
research/        — phishing-model training script, dataset, and results
                   (this is what produced app/ml_models/phishing_model.ubj)
```

## Quickstart (run it locally)

Requires **Python 3.12** (Python 3.14 is too new — several ML dependencies don't yet ship prebuilt wheels for it, which forces slow/error-prone source builds on Windows).

```bash
git clone <this-repo-url>
cd cybershield

python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS/Linux

pip install -r requirements.txt

copy .env.example .env         # Windows
cp .env.example .env           # macOS/Linux
# then edit SECRET_KEY to any random string

uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000, register an account, and try the tools from the dashboard. Full details, including optional local-LLM (Ollama) setup for the AI Advisor, are in [`cybershield/README.md`](cybershield/README.md).

## Reproducing the ML results

The trained phishing-detection model ships in the repo (`cybershield/app/ml_models/`), so you don't need to retrain to run the app. To reproduce or inspect the training process itself — including the three dataset-bias findings and fixes — see [`research/README.md`](research/README.md).

## Deployment

A one-click Render Blueprint (`cybershield/render.yaml`) is included for deploying a live instance with a PostgreSQL database. See the deployment section of `cybershield/README.md`.

## License

The original source code in this repository is MIT licensed — see [`LICENSE`](LICENSE). The dataset in `research/data/` is a third-party resource with its own terms (cited in `research/README.md`).
