"""
============================================================
  Deloitte Data Analytics Job Simulation
  Financial Fraud Detection System
  Skills: Python, Data Analysis, Data Modeling, Data Structures,
          Log Analysis, Data Visualization, Planning, Spreadsheets,
          Formal Communication, Web Security, Programming
  Author: Ashutosh Khalkho | Deloitte Forensic Technology Graduate
============================================================
"""

import math
import random
import statistics
from datetime import datetime, timedelta


# ─────────────────────────────────────────────────────────────
# 1. DATA GENERATION — Simulated Transaction Dataset
#    Skills: Data Structures, Python Programming, Planning
# ─────────────────────────────────────────────────────────────

MERCHANTS     = ["Amazon", "Walmart", "Zomato", "Swiggy", "Flipkart", "Unknown_Vendor", "Shell", "HDFC ATM", "Airtel", "BookMyShow"]
LOCATIONS     = ["Mumbai", "Delhi", "Bangalore", "Chennai", "Hyderabad", "Unknown", "Foreign_IP", "Kolkata", "Pune", "Jaipur"]
CATEGORIES    = ["E-Commerce", "Food", "ATM", "Fuel", "Telecom", "Entertainment", "Unknown", "International"]

def generate_transactions(n: int = 500, seed: int = 42) -> list[dict]:
    """
    Generates a simulated transaction log dataset.
    Demonstrates: Data Structures, Data Modeling, Python Programming
    """
    random.seed(seed)
    transactions = []

    base_date = datetime(2024, 1, 1)

    for i in range(n):
        is_fraud = random.random() < 0.08   # ~8% fraud rate

        if is_fraud:
            amount      = round(random.uniform(5000, 95000), 2)
            merchant    = random.choice(["Unknown_Vendor", "Foreign_IP", "Zomato", "Amazon"])
            location    = random.choice(["Unknown", "Foreign_IP", "Foreign_IP", "Unknown"])
            category    = random.choice(["Unknown", "International", "International"])
            hour        = random.choice([1, 2, 3, 23, 0])   # odd hours
            velocity    = random.randint(5, 20)              # many txns in short window
        else:
            amount      = round(random.uniform(50, 8000), 2)
            merchant    = random.choice(MERCHANTS[:8])
            location    = random.choice(LOCATIONS[:8])
            category    = random.choice(CATEGORIES[:6])
            hour        = random.randint(7, 22)
            velocity    = random.randint(1, 4)

        txn_date = base_date + timedelta(
            days=random.randint(0, 364),
            hours=hour,
            minutes=random.randint(0, 59)
        )

        transactions.append({
            "txn_id":       f"TXN{100000 + i}",
            "date":         txn_date.strftime("%Y-%m-%d"),
            "time":         txn_date.strftime("%H:%M"),
            "amount":       amount,
            "merchant":     merchant,
            "location":     location,
            "category":     category,
            "hour":         hour,
            "velocity_1h":  velocity,
            "is_fraud":     is_fraud,
        })

    return transactions


# ─────────────────────────────────────────────────────────────
# 2. RULE-BASED FRAUD DETECTION ENGINE
#    Skills: Log Analysis, Data Analysis, Algorithm Dev, Planning
# ─────────────────────────────────────────────────────────────

FRAUD_RULES = {
    "R01": {"desc": "High amount transaction (>₹50,000)",      "weight": 30},
    "R02": {"desc": "Unknown or suspicious merchant",           "weight": 25},
    "R03": {"desc": "Transaction from foreign/unknown location","weight": 20},
    "R04": {"desc": "Transaction at odd hours (12AM–5AM)",      "weight": 20},
    "R05": {"desc": "High velocity (>5 txns in 1 hour)",        "weight": 25},
    "R06": {"desc": "International category transaction",       "weight": 15},
    "R07": {"desc": "Round amount (potential structuring)",     "weight": 10},
}

def apply_fraud_rules(txn: dict) -> dict:
    """
    Applies rule-based scoring to each transaction.
    Demonstrates: Log Analysis, Data Modeling, Critical Thinking
    """
    flags   = []
    score   = 0

    if txn["amount"] > 50000:
        flags.append("R01"); score += FRAUD_RULES["R01"]["weight"]

    if txn["merchant"] in ["Unknown_Vendor", "Foreign_IP"]:
        flags.append("R02"); score += FRAUD_RULES["R02"]["weight"]

    if txn["location"] in ["Unknown", "Foreign_IP"]:
        flags.append("R03"); score += FRAUD_RULES["R03"]["weight"]

    if txn["hour"] in [0, 1, 2, 3, 4, 23]:
        flags.append("R04"); score += FRAUD_RULES["R04"]["weight"]

    if txn["velocity_1h"] > 5:
        flags.append("R05"); score += FRAUD_RULES["R05"]["weight"]

    if txn["category"] in ["International", "Unknown"]:
        flags.append("R06"); score += FRAUD_RULES["R06"]["weight"]

    if txn["amount"] % 1000 == 0:
        flags.append("R07"); score += FRAUD_RULES["R07"]["weight"]

    # Classify risk level
    if score >= 60:   risk = "CRITICAL"
    elif score >= 40: risk = "HIGH"
    elif score >= 20: risk = "MEDIUM"
    else:             risk = "LOW"

    return {**txn, "fraud_score": score, "flags": flags, "risk_level": risk}


# ─────────────────────────────────────────────────────────────
# 3. STATISTICAL ANALYSIS MODULE
#    Skills: Data Analysis, Data Visualization, Spreadsheet Skills
# ─────────────────────────────────────────────────────────────

def compute_statistics(scored: list[dict]) -> dict:
    """
    Computes key analytical metrics on the transaction dataset.
    Demonstrates: Data Analysis, Statistics, Spreadsheet Skills
    """
    total       = len(scored)
    fraud_txns  = [t for t in scored if t["risk_level"] in ["CRITICAL","HIGH"]]
    amounts     = [t["amount"] for t in scored]
    fraud_amt   = [t["amount"] for t in fraud_txns]

    fraud_rate  = len(fraud_txns) / total * 100

    # Amount distribution
    mean_amt    = statistics.mean(amounts)
    median_amt  = statistics.median(amounts)
    std_amt     = statistics.stdev(amounts)

    # Rule trigger frequency
    rule_counts = {r: 0 for r in FRAUD_RULES}
    for t in scored:
        for f in t["flags"]:
            rule_counts[f] += 1

    # Risk distribution
    risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in scored:
        risk_dist[t["risk_level"]] += 1

    # Category breakdown
    cat_fraud = {}
    for t in fraud_txns:
        cat_fraud[t["category"]] = cat_fraud.get(t["category"], 0) + 1

    return {
        "total_transactions":   total,
        "flagged_high_critical": len(fraud_txns),
        "fraud_rate_pct":       round(fraud_rate, 2),
        "total_amount":         round(sum(amounts), 2),
        "flagged_amount":       round(sum(fraud_amt), 2),
        "mean_txn_amount":      round(mean_amt, 2),
        "median_txn_amount":    round(median_amt, 2),
        "std_txn_amount":       round(std_amt, 2),
        "risk_distribution":    risk_dist,
        "rule_trigger_counts":  rule_counts,
        "top_fraud_categories": sorted(cat_fraud.items(), key=lambda x: -x[1])[:5],
        "actual_fraud_count":   sum(1 for t in scored if t["is_fraud"]),
    }


# ─────────────────────────────────────────────────────────────
# 4. MODEL EVALUATION — Precision, Recall, F1
#    Skills: Data Modeling, Programming, Data Analysis
# ─────────────────────────────────────────────────────────────

def evaluate_model(scored: list[dict]) -> dict:
    """
    Evaluates detection accuracy against ground truth labels.
    Demonstrates: Data Modeling, Statistical Analysis
    """
    tp = sum(1 for t in scored if t["risk_level"] in ["CRITICAL","HIGH"] and t["is_fraud"])
    fp = sum(1 for t in scored if t["risk_level"] in ["CRITICAL","HIGH"] and not t["is_fraud"])
    fn = sum(1 for t in scored if t["risk_level"] not in ["CRITICAL","HIGH"] and t["is_fraud"])
    tn = sum(1 for t in scored if t["risk_level"] not in ["CRITICAL","HIGH"] and not t["is_fraud"])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = (tp + tn) / len(scored)

    return {
        "true_positives":  tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives":  tn,
        "precision":       round(precision * 100, 2),
        "recall":          round(recall * 100, 2),
        "f1_score":        round(f1 * 100, 2),
        "accuracy":        round(accuracy * 100, 2),
    }


# ─────────────────────────────────────────────────────────────
# 5. ANOMALY DETECTION — Z-Score Method
#    Skills: Data Modeling, Python, Statistical Analysis
# ─────────────────────────────────────────────────────────────

def detect_anomalies(transactions: list[dict], threshold: float = 2.5) -> list[dict]:
    """
    Flags statistically anomalous transaction amounts using Z-scores.
    Demonstrates: Data Modeling, Statistical Analysis, Python Programming
    """
    amounts = [t["amount"] for t in transactions]
    mean    = statistics.mean(amounts)
    std     = statistics.stdev(amounts)

    anomalies = []
    for t in transactions:
        z = (t["amount"] - mean) / std
        if abs(z) > threshold:
            anomalies.append({**t, "z_score": round(z, 3)})

    return sorted(anomalies, key=lambda x: -abs(x["z_score"]))


# ─────────────────────────────────────────────────────────────
# 6. FORMAL REPORT GENERATOR
#    Skills: Formal Communication, Planning, Data Visualization
# ─────────────────────────────────────────────────────────────

def generate_report(stats: dict, model: dict, anomalies: list[dict]) -> str:
    """
    Generates a formatted forensic investigation report.
    Demonstrates: Formal Communication, Planning, Reporting
    """
    report = f"""
{'='*65}
  DELOITTE FORENSIC TECHNOLOGY
  FINANCIAL FRAUD INVESTIGATION REPORT
  Prepared by: Ashutosh Khalkho | Data Analytics Simulation
  Date: {datetime.now().strftime('%B %d, %Y')}
{'='*65}

EXECUTIVE SUMMARY
─────────────────
Total Transactions Analysed : {stats['total_transactions']:,}
High/Critical Risk Flagged  : {stats['flagged_high_critical']:,}
Fraud Detection Rate        : {stats['fraud_rate_pct']}%
Total Transaction Value     : ₹{stats['total_amount']:,.2f}
Value at Risk (Flagged)     : ₹{stats['flagged_amount']:,.2f}

RISK DISTRIBUTION
─────────────────
  CRITICAL  : {stats['risk_distribution']['CRITICAL']:>5} transactions
  HIGH      : {stats['risk_distribution']['HIGH']:>5} transactions
  MEDIUM    : {stats['risk_distribution']['MEDIUM']:>5} transactions
  LOW       : {stats['risk_distribution']['LOW']:>5} transactions

MODEL PERFORMANCE METRICS
──────────────────────────
  Accuracy    : {model['accuracy']}%
  Precision   : {model['precision']}%
  Recall      : {model['recall']}%
  F1 Score    : {model['f1_score']}%

  Confusion Matrix:
    True Positives  (TP): {model['true_positives']}
    False Positives (FP): {model['false_positives']}
    False Negatives (FN): {model['false_negatives']}
    True Negatives  (TN): {model['true_negatives']}

STATISTICAL ANALYSIS
─────────────────────
  Mean Transaction Amount   : ₹{stats['mean_txn_amount']:,.2f}
  Median Transaction Amount : ₹{stats['median_txn_amount']:,.2f}
  Std Deviation             : ₹{stats['std_txn_amount']:,.2f}

TOP FRAUD CATEGORIES
─────────────────────"""

    for cat, cnt in stats['top_fraud_categories']:
        report += f"\n  {cat:<25}: {cnt} flagged transactions"

    report += f"""

TOP ANOMALOUS TRANSACTIONS (Z-Score Method)
────────────────────────────────────────────
  {'TXN ID':<12} {'Amount':>12} {'Z-Score':>8} {'Merchant':<20} {'Location'}"""

    for a in anomalies[:5]:
        report += f"\n  {a['txn_id']:<12} ₹{a['amount']:>10,.2f} {a['z_score']:>8} {a['merchant']:<20} {a['location']}"

    report += f"""

RULE ENGINE TRIGGER SUMMARY
─────────────────────────────"""

    for rule_id, info in FRAUD_RULES.items():
        count = stats['rule_trigger_counts'].get(rule_id, 0)
        report += f"\n  [{rule_id}] {info['desc']:<45} Triggered: {count}x"

    report += f"""

RECOMMENDATIONS
────────────────
  1. Immediately review all CRITICAL-flagged transactions with compliance team.
  2. Block transactions from Foreign_IP and Unknown locations pending verification.
  3. Implement real-time velocity checks to limit transactions per hour per account.
  4. Escalate structuring-pattern transactions (R07) to AML division.
  5. Enhance ML model with supervised learning on confirmed fraud labels.

{'='*65}
  CONFIDENTIAL — FOR INTERNAL USE ONLY
  Deloitte Forensic Technology | Data Analytics Division
{'='*65}
"""
    return report


# ─────────────────────────────────────────────────────────────
# 7. MAIN — FULL PIPELINE
# ─────────────────────────────────────────────────────────────

def run_pipeline():
    print("=" * 65)
    print("  DELOITTE — FINANCIAL FRAUD DETECTION SYSTEM")
    print("  Ashutosh Khalkho | Data Analytics Job Simulation")
    print("=" * 65)

    print("\n[1/5] Generating transaction dataset...")
    transactions = generate_transactions(n=500)
    print(f"      ✓ {len(transactions)} transactions generated")

    print("[2/5] Applying fraud detection rules...")
    scored = [apply_fraud_rules(t) for t in transactions]
    print(f"      ✓ Rule engine applied to all transactions")

    print("[3/5] Computing statistical analysis...")
    stats = compute_statistics(scored)
    print(f"      ✓ Fraud rate: {stats['fraud_rate_pct']}%")

    print("[4/5] Evaluating model performance...")
    model = evaluate_model(scored)
    print(f"      ✓ F1 Score: {model['f1_score']}% | Accuracy: {model['accuracy']}%")

    print("[5/5] Detecting statistical anomalies...")
    anomalies = detect_anomalies(transactions)
    print(f"      ✓ {len(anomalies)} anomalous transactions detected")

    print("\n" + generate_report(stats, model, anomalies))

    # Top 10 flagged transactions
    critical = sorted([t for t in scored if t["risk_level"] == "CRITICAL"],
                      key=lambda x: -x["fraud_score"])[:10]
    print(f"\n{'─'*65}")
    print("  TOP 10 CRITICAL TRANSACTIONS")
    print(f"{'─'*65}")
    print(f"  {'TXN ID':<12} {'Amount':>10} {'Score':>6} {'Merchant':<20} {'Location'}")
    for t in critical:
        print(f"  {t['txn_id']:<12} ₹{t['amount']:>8,.0f} {t['fraud_score']:>6} {t['merchant']:<20} {t['location']}")


if __name__ == "__main__":
    run_pipeline()
