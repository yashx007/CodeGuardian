
# 🛡️ CodeGuardian: The Autonomous AI DevSecOps Agent

> **An intelligent, agentic AI system that analyzes, explains, and auto-fixes code vulnerabilities — powered by NVIDIA NIM and AWS SageMaker.**


## Overview

**CodeGuardian** is an **AI-powered DevSecOps agent** that automatically scans source code, detects security risks, explains vulnerabilities in natural language, and suggests secure fixes.

It combines **static analysis** (like a linter) with **LLM-based reasoning** (like an expert security reviewer) — running as an **agentic system** powered by:

- **NVIDIA NIM Inference Microservices**  
  - `llama-3-1-nemotron-nano-8B-v1` → reasoning and fix generation  
  - `retrieval-embedding-nim` → knowledge retrieval  
- ☁️ **AWS SageMaker Endpoints** for scalable inference  
- ⚙️ **FastAPI backend** and lightweight Python agent framework  



## Goal

To make **secure software development autonomous**, by allowing developers to:

1. Upload or scan code automatically.  
2. Detect insecure patterns and dependencies.  
3. Get **human-like explanations and secure fix suggestions**.  
4. Continuously learn from known vulnerabilities via a knowledge base (KB).  



## Key Features

| Feature | Description |
|----------|-------------|
| 🔍 **Static Code Analysis** | Parses Python, JS, and C/C++ code for dangerous patterns, insecure APIs, and secrets. |
| 🧠 **AI Reasoning (NVIDIA NIM)** | Uses `llama-3-1-nemotron-nano-8B-v1` to explain each issue and propose fixes. |
| 📚 **Retrieval-Augmented Knowledge Base** | Embeds security best practices (OWASP, CWE) via `retrieval-embedding-nim`. |
| 💬 **Interactive Chat Agent** | Allows developers to discuss findings and request clarifications. |
| 🧾 **Risk Summarization** | Generates an overall project risk score (Low / Medium / High) with rationale. |
| ☁️ **AWS-Ready Deployment** | Deployable via Amazon SageMaker or Amazon EKS with Docker support. |



## Architecture

```

```
            ┌──────────────────────────────┐
            │          Developer           │
            └──────────────┬───────────────┘
                           │
                           ▼
                ┌────────────────────┐
                │     FastAPI App     │
                │ (app/app.py, /api) │
                └────────┬───────────┘
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
```

┌─────────────────────┐          ┌──────────────────────┐
│  Static Analyzer    │          │   Reasoning Engine    │
│ (agent/parser.py)   │          │ (agent/reasoning.py)  │
└─────────┬───────────┘          └──────────┬────────────┘
│                                 │
▼                                 ▼
┌──────────────────────┐       ┌────────────────────────┐
│ Knowledge Store (KB) │◄────►│ NVIDIA NIM (SageMaker) │
│  (FAISS / Embedding) │       │ Llama-3 + Embedding NIM │
└──────────────────────┘       └────────────────────────┘

```



## Folder Structure

```

CodeGuardian/
│
├── agent/
│   ├── parser.py             # Static analyzer (Stage 2)
│   ├── reasoning.py          # AI reasoning engine (Stage 3–4)
│   ├── aws_client.py         # SageMaker integration (Stage 4)
│   ├── knowledge_base.py     # Seeded security KB
│   ├── knowledge_store.py    # Retrieval & embedding logic
│   ├── persistence.py        # Optional SQLite persistence
│   └── **init**.py
│
├── app/
│   ├── app.py                # FastAPI app entry
│   ├── routes_chat.py        # Interactive chat endpoint
│   ├── routes_summary.py     # Risk summary API
│   └── **init**.py
│
├── tests/
│   ├── test_parser.py
│   ├── test_reasoning.py
│   ├── test_aws_client.py
│   └── ...
│
├── input/                    # Sample test code files
│
├── .github/workflows/
│   └── ci.yml                # Linting + test pipeline
│
├── Dockerfile
├── requirements.txt
├── .env.example
└── README.md

````


## Setup Instructions

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/CodeGuardian.git
cd CodeGuardian
````

### 2️⃣ Create a Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Configure Environment Variables

Create a `.env` file:

```bash
AWS_ACCESS_KEY_ID=<your-aws-access-key>
AWS_SECRET_ACCESS_KEY=<your-aws-secret-key>
AWS_REGION=us-east-1
LLM_ENDPOINT_NAME=llama3-nim-endpoint
EMBED_ENDPOINT_NAME=retrieval-embed-endpoint
```


## AWS & NIM Integration Setup

### Step 1 — Deploy NIM Models on SageMaker

* Go to **AWS Console → SageMaker → Inference → Endpoints**
* Deploy:

  * `llama-3-1-nemotron-nano-8B-v1`
  * `retrieval-embedding-nim`
* Copy their **endpoint names**.

### Step 2 — Verify Access

```bash
aws sagemaker list-endpoints
```

### Step 3 — Run Locally with NIM Enabled

```bash
uvicorn app.app:app --reload
```

Then test:

```
POST /analyze
Content: { "path": "input/" }
```

You’ll get JSON output containing:

* Static findings
* AI-generated explanations & fixes
* Risk summary


## Example Output

```json
{
  "file": "test_insecure.py",
  "findings": [
    {
      "type": "Hardcoded Secret",
      "line": 7,
      "severity": "High",
      "message": "Avoid hardcoding passwords; use env vars or secret stores.",
      "ai_fix": "Replace password with environment variable reference."
    },
    {
      "type": "Insecure Function Usage",
      "line": 12,
      "message": "Use of eval() can lead to injection.",
      "ai_fix": "Remove eval() or validate input properly."
    }
  ],
  "overall_risk": "High"
}
```


## Example API Endpoints

| Endpoint   | Method | Description                              |
| ---------- | ------ | ---------------------------------------- |
| `/analyze` | POST   | Analyze a file/folder for issues         |
| `/summary` | GET    | Get project-wide risk summary            |
| `/chat`    | POST   | Ask questions about issues interactively |


## Running Tests

```bash
pytest -v
```

CI also runs automatically via GitHub Actions:

* Lint (flake8)
* Unit tests (pytest)
* Optional embedding index build


## Docker Setup

Build and run locally:

```bash
docker build -t codeguardian .
docker run -p 8080:8080 codeguardian
```

Access: `http://localhost:8080/docs`


## Knowledge Base (KB)

Includes 50+ security patterns and best practices:

* OWASP Top 10
* CWE references
* Python, JS, and C/C++ insecure APIs
* Example fixes and recommended libraries

Stored in `agent/knowledge_base.py` and indexed via Embedding NIM.


## Technologies Used

| Area             | Stack                                |
| ---------------- | ------------------------------------ |
| Language         | Python 3.11+                         |
| Framework        | FastAPI                              |
| AI Models        | NVIDIA NIM (Llama-3, Embedding NIM)  |
| Cloud            | AWS SageMaker                        |
| Storage          | SQLite (optional)                    |
| CI/CD            | GitHub Actions                       |
| Containerization | Docker                               |
| Infra            | EKS or SageMaker endpoint deployment |


## Contribution Guide

Want to improve CodeGuardian?

1. Fork this repo
2. Create a new branch (`feature/add-chat-ui`)
3. Commit your changes
4. Submit a pull request 🚀


## Future Roadmap

* [ ] Add browser-based chat UI
* [ ] Multi-language (Java, Go) analyzers
* [ ] Continuous scan mode via GitHub Actions
* [ ] Dashboard for risk visualization
* [ ] Integration with AWS CodePipeline


## Acknowledgements

Special thanks to:

* **AWS & NVIDIA** for providing compute and NIM microservices.
* **OpenAI & FastAPI** for enabling rapid AI backend development.
* **OWASP/CWE** for the foundational security knowledge base.



> *"CodeGuardian — making secure coding autonomous, one commit at a time."*

