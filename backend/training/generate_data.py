"""Synthetic training-data generator.

Produces a CSV of (text, label, spans) where label ∈ {0, 1}.
- 0 = benign / non-sensitive
- 1 = contains sensitive content

Covers realistic LLM usage patterns: developer debugging, business writing,
data analysis, code review, HR/legal/medical queries — both request and
response directions, including multi-turn chat format.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import string
from pathlib import Path

# ─── Word banks ──────────────────────────────────────────────────────────────

FIRST_NAMES = [
    "Alex", "Priya", "Mei", "Jordan", "Samira", "Diego", "Hannah",
    "Chris", "Tomás", "Aisha", "Wei", "Olivia", "Marcus", "Yuki",
    "Fatima", "Noah", "Isabella", "Liam", "Ava", "Ethan", "Sofia",
    "James", "Amara", "Lucas", "Zara", "Daniel", "Chloe", "Ryan",
    "Nadia", "Kevin", "Elena", "Omar", "Grace", "Sean", "Layla",
]
LAST_NAMES = [
    "Patel", "Smith", "Nguyen", "Garcia", "Kim", "Johansson", "Okafor",
    "Brown", "Müller", "Tanaka", "Mendoza", "Lee", "Petrov", "Clarke",
    "Williams", "Chen", "Rossi", "Ahmed", "Kowalski", "Santos", "Dubois",
    "Zhang", "Andersen", "Ivanova", "Yamamoto", "Fernandez", "O'Brien",
]
COMPANIES = [
    "Acme Robotics", "Northwind Logistics", "Helix Biotech", "Aurora Capital",
    "Pinecone Health", "Stellar Foods", "Bluebird Insurance", "Quantum Analytics",
    "Meridian Software", "Apex Consulting", "Ironbridge Finance", "Vortex AI",
    "Cascade Cloud", "Summit Legal", "Granite Manufacturing", "Cobalt Security",
]
ROLES = [
    "VP of Engineering", "Lead Counsel", "CFO", "CISO", "Head of HR",
    "Senior Software Engineer", "Data Scientist", "DevOps Engineer",
    "Product Manager", "Security Analyst", "Backend Developer",
    "Machine Learning Engineer", "SRE", "CTO", "Principal Architect",
]
TECH_STACKS = [
    "Python/FastAPI", "Node.js/Express", "Go/gRPC", "Java/Spring Boot",
    "Ruby on Rails", "Rust/Axum", "TypeScript/Next.js", "Django/PostgreSQL",
]
CLOUD_ENVS = ["AWS", "GCP", "Azure", "DigitalOcean", "Fly.io", "Railway"]
REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-1", "us-west-2", "eu-central-1"]
DB_NAMES = ["customers", "users", "orders", "analytics", "payments", "prod_main"]
PROJECTS = [
    "Project Atlas", "Operation Firebird", "Initiative Cobalt",
    "Rebranding 2025", "Q4 Roadmap", "Series B Deck", "M&A Target Analysis",
]
HOSPITALS = [
    "Mercy General Hospital", "St. Luke's Medical Center", "Riverside Clinic",
    "Northeast Medical Group", "Valley Health System",
]
DIAGNOSES = [
    "type 2 diabetes", "hypertension", "major depressive disorder",
    "atrial fibrillation", "chronic kidney disease", "hypothyroidism",
    "anxiety disorder", "sleep apnea", "COPD", "rheumatoid arthritis",
]
MEDICATIONS = [
    "metformin 1000mg", "lisinopril 10mg", "atorvastatin 40mg",
    "sertraline 50mg", "levothyroxine 75mcg", "amlodipine 5mg",
]

# ─── Credential / PII generators ─────────────────────────────────────────────

def _rand_email(company: str | None = None) -> str:
    first = random.choice(FIRST_NAMES).lower()
    last  = random.choice(LAST_NAMES).lower()
    if company:
        domain = company.lower().replace(" ", "") + ".com"
    else:
        domain = random.choice(["gmail.com", "outlook.com", "yahoo.com",
                                 "acme.co", "northwind.io", "helix.bio",
                                 "protonmail.com", "icloud.com"])
    sep = random.choice([".", "_", ""])
    return f"{first}{sep}{last}{random.randint(1, 99)}@{domain}"


def _rand_phone() -> str:
    fmt = random.choice([
        f"+1-{random.randint(200,999)}-{random.randint(200,999)}-{random.randint(1000,9999)}",
        f"({random.randint(200,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}",
        f"+44 {random.randint(7000,7999)} {random.randint(100000,999999)}",
        f"+91-{random.randint(7000,9999)}-{random.randint(100000,999999)}",
    ])
    return fmt


def _rand_ssn() -> str:
    return f"{random.randint(100,799)}-{random.randint(10,99)}-{random.randint(1000,9999)}"


def _rand_dob() -> str:
    return f"{random.randint(1,12):02d}/{random.randint(1,28):02d}/{random.randint(1940,2000)}"


def _rand_credit_card() -> str:
    prefix = random.choice(["4", "5", "37", "6011"])
    digits = list(prefix) + [str(random.randint(0,9)) for _ in range(16 - len(prefix) - 1)]
    total = 0
    for i, d in enumerate(reversed([int(x) for x in digits])):
        n = d * 2 if i % 2 == 0 else d
        total += n - 9 if n > 9 else n
    digits.append(str((10 - total % 10) % 10))
    raw = "".join(digits)
    return f"{raw[:4]} {raw[4:8]} {raw[8:12]} {raw[12:]}"


def _rand_iban() -> str:
    country = random.choice(["GB", "DE", "FR", "NL", "ES"])
    return f"{country}{random.randint(10,99)}{''.join([str(random.randint(0,9)) for _ in range(18)])}"


def _rand_aws_key() -> str:
    return "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))


def _rand_aws_secret() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits + "/+", k=40))


def _rand_openai_key() -> str:
    return "sk-" + "".join(random.choices(string.ascii_letters + string.digits, k=48))


def _rand_anthropic_key() -> str:
    return "sk-ant-api03-" + "".join(random.choices(string.ascii_letters + string.digits + "-_", k=80))


def _rand_gh_token() -> str:
    prefix = random.choice(["ghp_", "gho_", "ghs_", "github_pat_"])
    return prefix + "".join(random.choices(string.ascii_letters + string.digits, k=36))


def _rand_jwt() -> str:
    def part(n: int) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits + "_-", k=n))
    return f"eyJ{part(20)}.{part(60)}.{part(43)}"


def _rand_password() -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    length = random.randint(12, 20)
    return "".join(random.choices(chars, k=length))


def _rand_db_url(db: str | None = None) -> str:
    db = db or random.choice(DB_NAMES)
    host = f"db-{'prod' if random.random() > 0.3 else 'staging'}-{random.randint(1,5)}.internal.{random.choice(COMPANIES).lower().replace(' ','')}.com"
    return f"postgresql://admin:{_rand_password()}@{host}:5432/{db}"


def _rand_internal_host() -> str:
    env   = random.choice(["prod", "staging", "dev"])
    svc   = random.choice(["vault", "redis", "kafka", "k8s-master", "bastion", "jenkins", "grafana"])
    num   = random.randint(1, 9)
    co    = random.choice(COMPANIES).lower().replace(" ", "")
    tld   = random.choice(["com", "io", "co", "internal"])
    return f"{svc}-{num}.{env}.{co}.{tld}"


def _rand_ip_private() -> str:
    return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def _rand_stripe_key() -> str:
    prefix = random.choice(["sk_live_", "sk_test_", "pk_live_"])
    return prefix + "".join(random.choices(string.ascii_letters + string.digits, k=32))


def _rand_slack_token() -> str:
    return "xoxb-" + "-".join(
        "".join(random.choices(string.digits, k=n)) for n in [12, 12, 24]
    )


# ─── Sensitive content blocks ─────────────────────────────────────────────────

def _env_file_block() -> str:
    """Realistic .env file snippet."""
    lines = [
        f"DATABASE_URL={_rand_db_url()}",
        f"SECRET_KEY={_rand_password()}",
        f"OPENAI_API_KEY={_rand_openai_key()}",
        f"AWS_ACCESS_KEY_ID={_rand_aws_key()}",
        f"AWS_SECRET_ACCESS_KEY={_rand_aws_secret()}",
        f"STRIPE_SECRET_KEY={_rand_stripe_key()}",
        f"JWT_SECRET={_rand_password()}",
        f"REDIS_URL=redis://:{_rand_password()}@{_rand_internal_host()}:6379/0",
        f"SLACK_BOT_TOKEN={_rand_slack_token()}",
        f"SENDGRID_API_KEY=SG.{''.join(random.choices(string.ascii_letters + string.digits, k=60))}",
    ]
    chosen = random.sample(lines, k=random.randint(3, 6))
    return "\n".join(chosen)


def _code_with_secret() -> str:
    """Code snippet with a hardcoded credential."""
    templates = [
        f'const client = new OpenAI({{ apiKey: "{_rand_openai_key()}" }});\nconst response = await client.chat.completions.create({{...}});',
        f'anthropic = Anthropic(api_key="{_rand_anthropic_key()}")\nmessage = anthropic.messages.create(model="claude-3-opus-20240229", ...)',
        f'conn = psycopg2.connect("{_rand_db_url()}")\ncursor = conn.cursor()',
        f'AWS_KEY = "{_rand_aws_key()}"\nAWS_SECRET = "{_rand_aws_secret()}"\nboto3.Session(aws_access_key_id=AWS_KEY, aws_secret_access_key=AWS_SECRET)',
        f'curl -H "Authorization: Bearer {_rand_gh_token()}" https://api.github.com/user/repos',
        f'headers = {{"Authorization": "Bearer {_rand_jwt()}"}}\nrequests.post("https://api.example.com/v1/data", headers=headers)',
        f'GITHUB_TOKEN="{_rand_gh_token()}" gh repo clone org/private-repo',
        f'export STRIPE_KEY="{_rand_stripe_key()}"\npython run_charge.py --amount 9900',
    ]
    return random.choice(templates)


def _pii_record() -> str:
    """Realistic PII-heavy text."""
    first = random.choice(FIRST_NAMES)
    last  = random.choice(LAST_NAMES)
    templates = [
        f"Customer {first} {last} (DOB {_rand_dob()}, SSN {_rand_ssn()}) called to dispute "
        f"a charge of ${random.randint(50,2000)} on card ending {_rand_credit_card()[-4:]}. "
        f"Email on file: {_rand_email()}. Phone: {_rand_phone()}.",

        f"Please update the billing info for {_rand_email()} — new card: {_rand_credit_card()}, "
        f"exp {random.randint(1,12):02d}/{random.randint(25,30)}, CVV {random.randint(100,999)}, "
        f"billing address: {random.randint(100,9999)} {random.choice(['Oak','Maple','Pine','Elm'])} "
        f"St, {random.choice(['Boston','Austin','Seattle','Denver'])}, "
        f"{random.choice(['MA','TX','WA','CO'])} {random.randint(10000,99999)}.",

        f"Candidate {first} {last}: DOB {_rand_dob()}, SSN {_rand_ssn()}, "
        f"current salary ${random.randint(80,350)}k, mobile {_rand_phone()}, "
        f"personal email {_rand_email()}. References available on request.",

        f"Wire transfer request: ${random.randint(10,950)},{random.randint(0,999):03d} "
        f"from account {random.randint(10000000,99999999)} "
        f"to IBAN {_rand_iban()}, recipient {first} {last}, "
        f"ref: {random.choice(['invoice','payment','settlement'])} #{random.randint(1000,9999)}.",

        f"Patient: {first} {last}, MRN {random.randint(100000,999999)}, "
        f"DOB {_rand_dob()}, insurance ID {random.randint(1000000,9999999)}, "
        f"phone {_rand_phone()}. Admitted {random.choice(HOSPITALS)}.",
    ]
    return random.choice(templates)


def _medical_record() -> str:
    first = random.choice(FIRST_NAMES)
    last  = random.choice(LAST_NAMES)
    diag  = random.choice(DIAGNOSES)
    med   = random.choice(MEDICATIONS)
    return random.choice([
        f"Patient {first} {last}, DOB {_rand_dob()}, MRN {random.randint(100000,999999)}. "
        f"Diagnosis: {diag}. Prescribed {med} twice daily. "
        f"Lab results: A1C {round(random.uniform(5.5,12.0),1)}, "
        f"creatinine {round(random.uniform(0.6,3.5),1)} mg/dL. "
        f"Next follow-up in {random.randint(2,12)} weeks.",

        f"CONFIDENTIAL — {random.choice(HOSPITALS)} discharge summary. "
        f"Name: {first} {last}. Condition: {diag}. "
        f"Medication: {med}. Mental health screening score: {random.randint(5,21)}/21. "
        f"Insurance: {random.choice(['BlueCross','Aetna','UnitedHealth','Cigna'])} "
        f"policy #{random.randint(100000000,999999999)}.",
    ])


def _financial_record() -> str:
    company = random.choice(COMPANIES)
    return random.choice([
        f"CONFIDENTIAL — {company} Q{random.randint(1,4)} forecast: "
        f"revenue ${random.randint(20,900)}M, EBITDA margin {random.randint(8,45)}%, "
        f"headcount reduction of {random.randint(3,18)}% planned. "
        f"Do not share outside the exec team until earnings call.",

        f"M&A target: {random.choice(COMPANIES)}. Offer price: "
        f"${random.randint(50,800)}M ({random.randint(4,20)}x ARR). "
        f"Signed NDA on file. Advisor: {random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)} "
        f"at {random.choice(['Goldman Sachs','JPMorgan','Morgan Stanley'])}.",

        f"Salary band update (not public): IC4 ${random.randint(140,180)}k base + "
        f"{random.randint(15,30)}% bonus, IC5 ${random.randint(180,240)}k + "
        f"{random.randint(20,40)}% bonus. Equity refresh pool: {random.randint(2,8)}M shares.",

        f"Investor update: {company} raised ${random.randint(5,120)}M Series "
        f"{random.choice(['A','B','C','D'])} led by {random.choice(['a16z','Sequoia','Tiger Global','Bessemer'])}. "
        f"Post-money valuation ${random.randint(50,2000)}M. Cap table attached — strictly confidential.",
    ])


def _infra_secret() -> str:
    return random.choice([
        f"Here is the prod SSH key for {_rand_internal_host()}:\n"
        f"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA{_rand_password()}"
        f"{''.join(random.choices(string.ascii_letters + string.digits + '/+', k=80))}\n"
        f"-----END RSA PRIVATE KEY-----",

        f"VPN config for {random.choice(FIRST_NAMES)}: server {_rand_internal_host()}, "
        f"pre-shared key {_rand_password()}, cert expires {random.randint(2025,2027)}-"
        f"{random.randint(1,12):02d}-{random.randint(1,28):02d}.",

        f"Kubernetes secret (base64): apiVersion: v1\nkind: Secret\n"
        f"data:\n  db-password: {''.join(random.choices(string.ascii_letters + string.digits, k=32))}==\n"
        f"  api-key: {''.join(random.choices(string.ascii_letters + string.digits, k=44))}",

        f"Production Terraform state includes:\n"
        f"  rds_password = \"{_rand_password()}\"\n"
        f"  jwt_secret   = \"{_rand_password()}\"\n"
        f"  stripe_key   = \"{_rand_stripe_key()}\"",
    ])


def _destructive_command() -> str:
    """Commands the model might suggest that look destructive."""
    return random.choice([
        f"To clean up the old data: `rm -rf /var/data/{'prod' if random.random()>0.5 else 'backup'}/*`",
        f"Drop the old table: `DROP TABLE {'users' if random.random()>0.5 else 'orders'} CASCADE;`",
        f"Reset the database: `psql -U admin -c 'DELETE FROM events; VACUUM FULL;'`",
        f"One-liner to nuke the cache: `redis-cli FLUSHALL && systemctl restart redis`",
        f"To revoke all tokens: `UPDATE users SET token = NULL; DELETE FROM sessions;`",
        f"Terraform destroy: `terraform destroy -auto-approve -target=module.prod_cluster`",
        f"kubectl: `kubectl delete namespace production --grace-period=0 --force`",
    ])


# ─── Benign content blocks ─────────────────────────────────────────────────────

_BENIGN_CODE = [
    "def fibonacci(n):\n    a, b = 0, 1\n    for _ in range(n): a, b = b, a+b\n    return a",
    "const debounce = (fn, ms) => {\n  let t;\n  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };\n};",
    "SELECT u.id, u.email, COUNT(o.id) AS orders\nFROM users u LEFT JOIN orders o ON o.user_id = u.id\nGROUP BY u.id ORDER BY orders DESC LIMIT 20;",
    "function quicksort(arr) {\n  if (arr.length <= 1) return arr;\n  const pivot = arr[0];\n  return [...quicksort(arr.filter(x => x < pivot)), pivot, ...quicksort(arr.filter(x => x > pivot))];\n}",
    "git log --oneline --graph --decorate --all | head -20",
    "docker compose up -d --build && docker compose logs -f warden-api",
    "for pod in $(kubectl get pods -n staging -o name); do kubectl logs $pod --tail=50; done",
    "@app.get('/api/health')\nasync def health():\n    return {'status': 'ok', 'version': VERSION}",
    "SELECT DATE_TRUNC('day', created_at), COUNT(*) FROM events\nWHERE created_at > NOW() - INTERVAL '30 days'\nGROUP BY 1 ORDER BY 1;",
    "npx prisma migrate dev --name add_user_roles && npx prisma generate",
]

_BENIGN_TOPICS = [
    ("explain", [
        "the CAP theorem and how it applies to distributed databases",
        "how a B-tree index speeds up database queries",
        "the difference between process and thread in Linux",
        "what happens when you type a URL into a browser",
        "how TLS handshake works step by step",
        "the observer pattern in software design",
        "eventual consistency vs strong consistency",
        "how a JWT is structured and verified",
        "the trade-offs between REST and GraphQL",
        "what a service mesh does and when you need one",
        "how Kubernetes handles pod scheduling",
        "the difference between a mutex and a semaphore",
        "how MVCC works in PostgreSQL",
        "the role of a content delivery network",
        "why functional programming avoids shared state",
    ]),
    ("write", [
        "a Python script that reads a CSV and outputs JSON",
        "a Dockerfile for a Python Flask app",
        "a GitHub Actions workflow that runs tests on PR",
        "a bash script to back up a PostgreSQL database daily",
        "unit tests for a function that validates email addresses",
        "a FastAPI endpoint with request validation and error handling",
        "a SQL migration to add an index on the created_at column",
        "a React hook that debounces a search input",
        "an nginx config for reverse-proxying to a Node.js app",
        "a Terraform module for an S3 bucket with lifecycle rules",
        "a pre-commit hook that runs black and isort",
        "a retry decorator with exponential backoff in Python",
        "a parametrized pytest fixture for a PostgreSQL test database",
        "a Kubernetes Deployment YAML for a stateless API",
    ]),
    ("help me", [
        "write a postmortem for a 2-hour database outage",
        "review this pull request description and suggest improvements",
        "draft a message to my team explaining we're rolling back this release",
        "outline a tech spec for a rate-limiting middleware",
        "write a job description for a senior backend engineer role",
        "plan a migration from a monolith to microservices",
        "summarize the pros and cons of our three vendor options",
        "draft talking points for the Q4 engineering all-hands",
        "write a runbook section for rotating AWS access keys",
        "create a checklist for a production deploy",
    ]),
]

_BENIGN_QUESTIONS = [
    "What is the recommended way to handle database migrations in a zero-downtime deploy?",
    "Should I use Redis or Memcached for caching session tokens?",
    "What's the best strategy for blue-green deployments on AWS ECS?",
    "How do I set up log aggregation with Loki and Grafana?",
    "What are the trade-offs between synchronous and asynchronous task processing?",
    "How should I structure error handling in a layered API architecture?",
    "Is it better to use an ORM or raw SQL for complex reporting queries?",
    "What's the idiomatic way to handle retries in Go using context deadlines?",
    "How do I write a technical design doc that junior engineers can follow?",
    "What monitoring metrics should every production service expose?",
    "How should I handle schema evolution in a microservices architecture?",
    "What's the difference between optimistic and pessimistic locking?",
    "How do I safely rotate a secret that's used by multiple services?",
    "What's the right way to version a REST API?",
    "How do I set up canary deployments with minimal risk?",
    "What should go in a good README for an internal library?",
    "Can you review my approach to pagination: I'm using offset/limit on a 10M-row table.",
    "What's the correct way to handle CORS in a FastAPI app?",
    "Should I use connection pooling or persistent connections for a high-traffic PostgreSQL workload?",
    "How do I debug a memory leak in a Python service running in Docker?",
]


def _benign_paragraph() -> str:
    """Generate a realistic, contextual benign LLM prompt."""
    choice = random.random()

    if choice < 0.15:
        return random.choice(_BENIGN_CODE)

    if choice < 0.30:
        return random.choice(_BENIGN_QUESTIONS)

    verb, topics = random.choice(_BENIGN_TOPICS)
    topic = random.choice(topics)
    stack = random.choice(TECH_STACKS)
    cloud = random.choice(CLOUD_ENVS)

    intros = [
        f"I'm working on a {stack} service deployed on {cloud}. {verb.capitalize()} {topic}.",
        f"Quick question for our team: {verb} {topic}.",
        f"We're doing a sprint planning session. Can you {verb} {topic}? Keep it practical.",
        f"I need help with something. Please {verb} {topic}.",
        f"Our tech lead asked me to {verb} {topic}. Here's the context: we're a {random.randint(5,80)}-person company using {stack}.",
        f"Can you {verb} {topic}? We're in the middle of a migration and time is short.",
        f"For a code review session: {verb} {topic}. Audience is senior engineers.",
    ]
    return random.choice(intros)


# ─── Multi-turn chat builders ─────────────────────────────────────────────────

def _chat_format(turns: list[tuple[str, str]], system: str | None = None) -> str:
    """Format as a realistic chat/messages API payload body."""
    lines: list[str] = []
    if system:
        lines.append(f"System: {system}")
    for role, content in turns:
        lines.append(f"{role}: {content}")
    return "\n\n".join(lines)


def _make_benign_chat() -> str:
    n_turns = random.randint(1, 4)
    system  = random.choice([
        None, None,  # usually no system prompt
        "You are a helpful software engineering assistant.",
        "You are an expert in cloud infrastructure and DevOps.",
        "You are a senior data scientist. Be concise and practical.",
        "You are a technical writer helping to improve documentation.",
    ])
    turns: list[tuple[str, str]] = []
    for i in range(n_turns):
        if i % 2 == 0:
            turns.append(("User", _benign_paragraph()))
        else:
            turns.append(("Assistant", _benign_response()))
    return _chat_format(turns, system)


def _benign_response() -> str:
    """A plausible short model reply to a technical question."""
    responses = [
        "Great question. The key trade-off here is between consistency and availability. "
        "For most web apps I'd recommend starting with a single primary and adding read replicas once you hit 1k QPS.",
        "Here's a minimal example:\n```python\ndef retry(fn, attempts=3, backoff=1.0):\n    for i in range(attempts):\n        try:\n            return fn()\n        except Exception:\n            if i == attempts - 1:\n                raise\n            time.sleep(backoff * 2**i)\n```",
        "The short answer is: use an index on `created_at` if you're filtering by time range, "
        "and consider a composite index if you're also filtering by `user_id`.",
        "For zero-downtime deploys, the standard approach is: (1) run migrations that are backwards-compatible, "
        "(2) deploy new code, (3) run clean-up migrations in a separate step after the old version is gone.",
        "I'd recommend Loki + Promtail for log aggregation — it's lightweight, integrates with Grafana natively, "
        "and the query language (LogQL) is similar to PromQL so your team won't need to learn another tool.",
        "The trade-off between REST and GraphQL comes down to your client diversity. "
        "If you have a single web client you control, REST is simpler. "
        "If you have mobile clients with different data requirements, GraphQL pays off.",
        "For session caching I'd go with Redis — it supports richer data structures, "
        "has better persistence options, and the ecosystem is more mature than Memcached.",
    ]
    return random.choice(responses)


def _make_sensitive_chat(category: str) -> str:
    """Build a realistic sensitive chat payload."""
    system = random.choice([None, None,
                             "You are a helpful assistant.",
                             "You are an AI assistant for Acme Corp employees."])
    preamble = random.choice([
        f"I need help with this. Here's the context:",
        f"Quick question —",
        f"Can you help me fix this issue?",
        f"I'm debugging something in prod. Here's the relevant info:",
        f"Pasting the config for you to review:",
        f"Here's the file:",
    ])
    sensitive = _sensitive_block(category)
    followup = random.choice([
        f"Does this look right to you?",
        f"Can you spot the bug?",
        f"What am I missing here?",
        f"Is there a better way to handle this?",
        f"How do I fix the authentication error?",
        "",
    ])
    turns: list[tuple[str, str]] = [
        ("User", f"{preamble}\n\n{sensitive}\n\n{followup}".strip()),
    ]
    if random.random() > 0.5:
        turns.append(("Assistant", _benign_response()))
        turns.append(("User", random.choice([
            "OK but the original error is still there.",
            "That didn't work, here's the updated version:",
            "Thanks, but can you also help me with the deployment?",
            "Can you double-check the credentials are correct?",
        ])))
    return _chat_format(turns, system)


def _sensitive_block(category: str) -> str:
    """Return one sensitive content block for the given category."""
    if category == "env_file":
        return _env_file_block()
    if category == "code_secret":
        return _code_with_secret()
    if category == "pii":
        return _pii_record()
    if category == "medical":
        return _medical_record()
    if category == "financial":
        return _financial_record()
    if category == "infra":
        return _infra_secret()
    if category == "destructive":
        return _destructive_command()
    # credentials
    return random.choice([
        f"username: admin\npassword: {_rand_password()}\nhost: {_rand_internal_host()}",
        f"API key: {_rand_openai_key()}",
        f"GitHub token: {_rand_gh_token()}",
        f"JWT: {_rand_jwt()}",
        f"Slack token: {_rand_slack_token()}",
    ])


SENSITIVE_CATEGORIES = [
    "env_file", "code_secret", "pii", "pii", "medical",
    "financial", "infra", "credentials", "destructive",
]

# ─── Sample builder ──────────────────────────────────────────────────────────

def _clean_text(s: str) -> str:
    """Normalise whitespace while preserving newlines as spaces."""
    return " ".join(s.split())


def _make_sample(label: int) -> tuple[str, list[tuple[int, int]]]:
    """Return (text, sensitive_spans). Spans empty for label=0."""
    if label == 0:
        use_chat = random.random() < 0.5
        text = _make_benign_chat() if use_chat else _benign_paragraph()
        # add some random benign filler for variety
        if random.random() < 0.3:
            text = text + " " + _benign_paragraph()
        return _clean_text(text), []

    # Sensitive sample
    category  = random.choice(SENSITIVE_CATEGORIES)
    use_chat  = random.random() < 0.6
    if use_chat:
        raw_text = _make_sensitive_chat(category)
    else:
        sensitive_block = _sensitive_block(category)
        preamble        = _benign_paragraph() if random.random() < 0.5 else ""
        suffix          = _benign_paragraph() if random.random() < 0.5 else ""
        raw_text        = f"{preamble} {sensitive_block} {suffix}".strip()

    text = _clean_text(raw_text)

    # Find char spans of sensitive block inside the cleaned text.
    # Best-effort: locate the cleaned version of the sensitive block.
    sensitive_clean = _clean_text(_sensitive_block(category))
    start = text.find(sensitive_clean[:40])   # first 40 chars as anchor
    if start >= 0:
        end = min(start + len(sensitive_clean), len(text))
        spans = [(start, end)]
    else:
        spans = []

    return text, spans


# ─── Public entry point ──────────────────────────────────────────────────────

def generate(n_samples: int, out_path: Path, seed: int = 7) -> None:
    random.seed(seed)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label", "spans"])
        for _ in range(n_samples):
            label       = 1 if random.random() < 0.5 else 0
            text, spans = _make_sample(label)
            writer.writerow([text, label, json.dumps(spans)])
    print(f"Wrote {n_samples} samples to {out_path}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--n",    type=int,  default=8000)
    p.add_argument("--out",  type=Path, default=Path("/models/training_data.csv"))
    p.add_argument("--seed", type=int,  default=7)
    args = p.parse_args()
    generate(args.n, args.out, seed=args.seed)


if __name__ == "__main__":
    main()
