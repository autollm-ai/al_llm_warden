"""Generate ~2000 fully unique Claude API calls through the warden proxy.
Each prompt is generated fresh via randomised templates — no duplicates.
Run: python scripts/gen_unique.py
"""
import json, os, random, requests, string, threading, time

token = json.load(open(os.path.expanduser("~/.claude/.credentials.json")))["claudeAiOauth"]["accessToken"]
PROXY = {"https": "http://localhost:8080", "http": "http://localhost:8080"}
CERT  = "D:/warden-ca.pem"
MODEL = "claude-haiku-4-5-20251001"

rng = random.Random()

FIRST = ["Alex","Priya","Jordan","Sam","Maya","Chris","Nina","Omar","Wei","Fatima","Lucas","Zara","Aisha","Diego","Hannah"]
LAST  = ["Smith","Patel","Garcia","Lee","Brown","Kim","Nguyen","Chen","Okafor","Dubois","Kowalski","Santos","Müller"]
COMPANIES = ["Acme Robotics","Helix Biotech","Northwind Logistics","Stellar Foods","Cascade Cloud","Apex Consulting","Vortex AI","Meridian Software"]
DIAGS   = ["type 2 diabetes","hypertension","atrial fibrillation","anxiety disorder","hypothyroidism","chronic migraine"]
MEDS    = ["metformin 1000mg","lisinopril 10mg","sertraline 50mg","levothyroxine 50mcg","amlodipine 5mg","propranolol 40mg"]
INSURE  = ["BlueCross","Aetna","UnitedHealth","Cigna","Humana","Kaiser"]
REGIONS = ["us-east-1","eu-west-1","ap-southeast-1","us-west-2","eu-central-1"]
SERIES  = ["A","B","C","D"]
TECHS   = ["Python/FastAPI","Node.js/Express","Go/gRPC","Java/Spring Boot","Django/PostgreSQL","Rust/Axum"]

def name():       return f"{rng.choice(FIRST)} {rng.choice(LAST)}"
def email():
    f, l = rng.choice(FIRST).lower(), rng.choice(LAST).lower()
    return f"{f}.{l}{rng.randint(1,99)}@{rng.choice(['corp.com','acme.co','gmail.com','outlook.com'])}"
def phone():      return f"+1-{rng.randint(200,999)}-{rng.randint(200,999)}-{rng.randint(1000,9999)}"
def dob():        return f"{rng.randint(1,12):02d}/{rng.randint(1,28):02d}/{rng.randint(1950,2000)}"
def ssn():        return f"{rng.randint(100,799)}-{rng.randint(10,99)}-{rng.randint(1000,9999)}"
def mrn():        return str(rng.randint(100000, 999999))
def card():       return f"4{rng.randint(100,999)} {rng.randint(1000,9999)} {rng.randint(1000,9999)} {rng.randint(1000,9999)}"
def aws_key():    return "AKIA" + "".join(rng.choices(string.ascii_uppercase + string.digits, k=16))
def aws_secret(): return "".join(rng.choices(string.ascii_letters + string.digits + "/+", k=40))
def oai_key():    return "sk-proj-" + "".join(rng.choices(string.ascii_letters + string.digits, k=48))
def gh_token():   return "ghp_" + "".join(rng.choices(string.ascii_letters + string.digits, k=36))
def stripe():     return "sk_live_" + "".join(rng.choices(string.ascii_letters + string.digits, k=24))
def jwt():        return "".join(rng.choices(string.ascii_letters + string.digits + "!@#%", k=32))
def db_pwd():     return "".join(rng.choices(string.ascii_letters + string.digits + "!@#", k=16))
def pem():        return "".join(rng.choices(string.ascii_letters + string.digits + "/+", k=64))
def rev():        return f"${rng.randint(40,900)}M ({rng.randint(10,70)}% YoY)"
def burn():       return f"${rng.randint(2,25)}M/month, {rng.randint(6,36)} months runway"
def region():     return rng.choice(REGIONS)
def tech():       return rng.choice(TECHS)
def company():    return rng.choice(COMPANIES)

BENIGN = [
    lambda: f"Explain {rng.choice(['consistent hashing','the CAP theorem','MVCC in PostgreSQL','exponential backoff','the saga pattern','CQRS','event sourcing','the circuit breaker pattern','rate limiting','the token bucket algorithm','blue-green deployments','chaos engineering','leader election in Raft','quorum reads','the fan-out problem','write-ahead logging','two-phase commit','vector clocks','backpressure','tail latency','the thundering herd problem','hot partitions','log compaction in Kafka'])} briefly.",
    lambda: f"What is the difference between {rng.choice(['TCP and UDP','SQL and NoSQL','optimistic and pessimistic locking','horizontal and vertical scaling','a mutex and a semaphore','REST and GraphQL','RDB and AOF persistence in Redis','B-trees and LSM trees','strong and eventual consistency','synchronous and asynchronous replication','monoliths and microservices','OLTP and OLAP','a process and a thread'])}?",
    lambda: f"Write a {rng.choice(['Python','Go','TypeScript','Java','Rust'])} function to implement {rng.choice(['a rate limiter','an LRU cache','exponential backoff with jitter','a distributed lock','a retry decorator','a circuit breaker','consistent hashing','a bloom filter'])}. Keep it concise.",
    lambda: f"How does {rng.choice(['Kafka guarantee ordering within a partition','Redis handle persistence with RDB vs AOF','Kubernetes schedule pods onto nodes','TLS 1.3 improve on TLS 1.2','PostgreSQL implement MVCC','Docker networking work','gRPC handle streaming','Prometheus scrape metrics','Elasticsearch index documents','Raft achieve consensus','Zookeeper handle leader election'])}? Brief.",
    lambda: f"Design a {rng.choice(['URL shortener','rate limiter','notification system','job scheduler','distributed cache','message queue','search autocomplete','leaderboard system','payment processing pipeline','content delivery network'])} system — key architectural decisions only.",
    lambda: f"What are the top 5 monitoring metrics every {tech()} service should expose and why?",
    lambda: f"Write a SQL query to {rng.choice(['find the top 10 customers by revenue in the last 30 days','detect duplicate records across two tables','calculate a 7-day rolling average','find users who placed orders but never returned','identify slow queries using pg_stat_statements'])}.",
    lambda: f"What causes {rng.choice(['PostgreSQL table bloat','Redis memory fragmentation','Kafka consumer lag','MySQL deadlocks','Elasticsearch split-brain','MongoDB WiredTiger cache pressure','connection pool exhaustion'])} and how do you fix it?",
]

SENSITIVE = [
    lambda: f"AWS creds not working: AWS_ACCESS_KEY_ID={aws_key()} AWS_SECRET_ACCESS_KEY={aws_secret()} region {region()}. Getting AccessDenied. Debug?",
    lambda: f"My .env is broken:\nDATABASE_URL=postgresql://admin:{db_pwd()}@prod-{rng.randint(1,5)}.internal.co:5432/customers\nOPENAI_API_KEY={oai_key()}\nJWT_SECRET={jwt()}\nGITHUB_TOKEN={gh_token()}\nSTRIPE_SECRET_KEY={stripe()}\nFix 401 error?",
    lambda: f"Patient note: {name()}, DOB {dob()}, SSN {ssn()}, MRN {mrn()}, {rng.choice(DIAGS)}, {rng.choice(MEDS)} twice daily, {rng.choice(INSURE)} #{rng.randint(100000000,999999999)}, contact {email()}, {phone()}. Summarise for referral.",
    lambda: f"Write a performance improvement plan for {name()}, IC{rng.randint(3,5)}, base ${rng.randint(90,250)}k, SSN {ssn()}. Issues: missed {rng.randint(3,8)} deadlines, inadequate documentation. Keep professional and under 100 words.",
    lambda: f"GitHub Actions token {gh_token()} is rejected in our CI. Workflow failing at deploy step. What could cause this?",
    lambda: f"Draft a refund email for customer {name()} ({email()}, card {card()}, phone {phone()}). Order #{rng.randint(10000,99999)}, amount ${rng.randint(20,800)}. Keep under 80 words.",
    lambda: f"Board deck review (confidential): {company()} Q{rng.randint(1,4)} revenue {rev()}, EBITDA {rng.randint(8,40)}%, burn {burn()}, planning Series {rng.choice(SERIES)} at ${rng.randint(20,300)}M. Write a 2-sentence exec summary.",
    lambda: f"Is this SSH key format valid?\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA{pem()}\n{pem()}\n-----END RSA PRIVATE KEY-----\nIt's for bastion-{rng.randint(1,5)}.prod.acme.io",
    lambda: f"Stripe live key {stripe()} returning 401 on our webhook endpoint. How do I debug this?",
    lambda: f"Boto3 broken:\nimport boto3\nsession = boto3.Session(\n    aws_access_key_id='{aws_key()}',\n    aws_secret_access_key='{aws_secret()}',\n    region_name='{region()}'\n)\nError: NoCredentialsError. Fix?",
    lambda: f"Medical record: {name()}, DOB {dob()}, MRN {mrn()}, SSN {ssn()}, {rng.choice(DIAGS)}, on {rng.choice(MEDS)}, {rng.choice(INSURE)} #{rng.randint(100000000,999999999)}. Write a discharge summary.",
    lambda: f"Term sheet (strictly confidential): Target: {company()}, valuation ${rng.randint(20,500)}M pre-money, {rng.randint(50,80)}% cash + equity, closing Q{rng.randint(1,4)} {rng.randint(2024,2026)}, exclusivity {rng.randint(30,60)} days. Summarise key risks.",
    lambda: f"Prod DB password rotation needed: postgresql://dbadmin:{db_pwd()}@{rng.randint(10,99)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}:5432/production_db. Steps for zero-downtime rotation?",
]

def make_prompt():
    if rng.random() < 0.6:
        return rng.choice(BENIGN)()
    return rng.choice(SENSITIVE)()

lock  = threading.Lock()
stats = {"ok": 0, "fail": 0, "done": 0}

def call(prompt):
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"Authorization": f"Bearer {token}", "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": MODEL, "max_tokens": 80, "messages": [{"role": "user", "content": prompt}]},
            proxies=PROXY, verify=CERT, timeout=60,
        )
        return r.json()["content"][0]["text"] if r.ok else None
    except:
        return None

def worker(count):
    for _ in range(count):
        result = call(make_prompt())
        with lock:
            stats["ok" if result else "fail"] += 1
            stats["done"] += 1
            if stats["done"] % 100 == 0:
                print(f'[{stats["done"]}/2000] ok={stats["ok"]} fail={stats["fail"]}', flush=True)
        time.sleep(1.0)

threads = [threading.Thread(target=worker, args=(1000,)) for _ in range(2)]
print("Starting 2 threads x 1000 = 2000 unique calls", flush=True)
t0 = time.time()
for t in threads: t.start()
for t in threads: t.join()
print(f'Done in {int(time.time()-t0)}s — ok={stats["ok"]} fail={stats["fail"]}')
