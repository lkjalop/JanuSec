# Learning Roadmap: From Intern to Expert

**Purpose**: Curated resources to master every concept in your platform

**Timeline**: 3-6 months of focused study

---

## How to Use This Roadmap

For each concept:
1. **Week 1**: Read foundational papers/books
2. **Week 2**: Hands-on labs/coding exercises
3. **Week 3**: Study production systems
4. **Week 4**: Implement advanced variant in your platform

**Goal**: Go from "I implemented it" → "I'm an expert who can teach others"

---

# Core Concepts

## 1. EWMA (Exponentially Weighted Moving Average)

### Foundational Reading (Week 1)
- **Book**: *Introduction to Time Series and Forecasting* by Brockwell & Davis
  - Chapter 2: "Stationary Processes and ARMA Models"
- **Paper**: "Exponentially Weighted Moving Average Control Charts" (Montgomery, 2009)
  - Focus: Section 3 on choosing alpha parameter
- **Online Course**: Coursera - "Practical Time Series Analysis"
  - Module 4: EWMA and exponential smoothing

### Hands-On (Week 2)
```python
# Exercise 1: Implement EWMA from scratch
import numpy as np
import matplotlib.pyplot as plt

def ewma(data, alpha=0.3):
    """
    Your implementation
    """
    result = [data[0]]  # Start with first value
    for i in range(1, len(data)):
        result.append(alpha * data[i] + (1 - alpha) * result[-1])
    return result

# Test with noisy data
np.random.seed(42)
signal = np.sin(np.linspace(0, 10, 100)) + np.random.normal(0, 0.5, 100)

# Compare different alphas
for alpha in [0.1, 0.3, 0.5, 0.7]:
    smoothed = ewma(signal, alpha)
    plt.plot(smoothed, label=f'α={alpha}')

plt.plot(signal, 'k.', alpha=0.3, label='Raw')
plt.legend()
plt.title('EWMA with Different Alpha Values')
plt.show()

# Exercise 2: Apply to security events
# Implement temporal risk decay for your platform
```

### Production Systems to Study (Week 3)
- **Prometheus**: Alerting rules use EWMA-like prediction
  - Read: https://prometheus.io/docs/prometheus/latest/querying/functions/#predict_linear
  - Study: How `rate()` and `irate()` use exponential weighting
- **Datadog APM**: Adaptive sampling based on EWMA
  - Read: https://docs.datadoghq.com/tracing/trace_pipeline/trace_retention/
  - Study: How they weight recent traces higher

### Advanced Implementation (Week 4)
**Project**: Multi-timeframe EWMA for your platform
```python
class MultiTimeframeEWMA:
    """
    Track risk across multiple windows:
    - Fast (α=0.7, 5-minute window) - Detect bursts
    - Medium (α=0.3, 1-hour window) - Detect campaigns
    - Slow (α=0.1, 24-hour window) - Detect slow-burn attacks
    """
    def __init__(self):
        self.fast_ewma = EWMA(alpha=0.7)
        self.medium_ewma = EWMA(alpha=0.3)
        self.slow_ewma = EWMA(alpha=0.1)

    def update(self, event_risk):
        fast = self.fast_ewma.update(event_risk)
        medium = self.medium_ewma.update(event_risk)
        slow = self.slow_ewma.update(event_risk)

        # Anomaly: fast > medium > slow = sudden spike
        if fast > medium * 1.5 and medium > slow * 1.3:
            return {'verdict': 'ATTACK_BURST', 'confidence': 0.9}

        return {'verdict': 'normal'}
```

---

## 2. TF-IDF (Term Frequency - Inverse Document Frequency)

### Foundational Reading (Week 1)
- **Book**: *Introduction to Information Retrieval* by Manning, Raghavan, Schütze
  - Chapter 6: "Scoring, term weighting, and the vector space model"
- **Paper**: "A Statistical Interpretation of Term Specificity" (Spärck Jones, 1972)
  - Original TF-IDF paper
- **Tutorial**: "TF-IDF from Scratch in Python" (TowardsDataScience)
  - Hands-on implementation guide

### Hands-On (Week 2)
```python
# Exercise 1: Build TF-IDF from scratch (no sklearn)
import math
from collections import Counter

class TFIDFVectorizer:
    def fit(self, documents):
        """
        Build vocabulary and IDF scores
        """
        self.vocab = set()
        self.doc_count = len(documents)
        self.idf = {}

        # Build vocab
        for doc in documents:
            tokens = doc.lower().split()
            self.vocab.update(tokens)

        # Calculate IDF
        for term in self.vocab:
            docs_with_term = sum(1 for doc in documents if term in doc.lower())
            self.idf[term] = math.log(self.doc_count / (1 + docs_with_term))

    def transform(self, document):
        """
        Convert document to TF-IDF vector
        """
        tokens = document.lower().split()
        term_freq = Counter(tokens)

        tfidf = {}
        for term, freq in term_freq.items():
            tf = freq / len(tokens)
            idf = self.idf.get(term, 0)
            tfidf[term] = tf * idf

        return tfidf

# Test
corpus = [
    "cmd.exe dir C:\\Users",
    "powershell.exe Get-Process",
    "python.exe script.py",
    "mimikatz.exe sekurlsa::logonpasswords"  # Rare!
]

vectorizer = TFIDFVectorizer()
vectorizer.fit(corpus)

test_doc = "mimikatz.exe sekurlsa::logonpasswords"
tfidf = vectorizer.transform(test_doc)
print(sorted(tfidf.items(), key=lambda x: x[1], reverse=True))
# 'mimikatz.exe' should have highest score (rare!)
```

### Production Systems to Study (Week 3)
- **Google Search**: TF-IDF for page ranking
  - Read: "The Anatomy of a Large-Scale Hypertextual Web Search Engine" (Brin & Page)
- **Spam Filters**: SpamAssassin uses TF-IDF
  - Read: https://spamassassin.apache.org/full/3.1.x/doc/Mail_SpamAssassin_Bayes.html
- **Darktrace**: Unsupervised learning for anomaly detection
  - Study: Their whitepapers on baseline learning

### Advanced Implementation (Week 4)
**Project**: Context-aware TF-IDF for command lines
```python
class CommandLineTFIDF:
    """
    Separate TF-IDF models for different contexts
    """
    def __init__(self):
        self.models = {
            'admin_user': TFIDFVectorizer(),
            'regular_user': TFIDFVectorizer(),
            'service_account': TFIDFVectorizer()
        }

    def fit(self, command_logs):
        """
        Train separate models per user type
        """
        for user_type, commands in command_logs.items():
            self.models[user_type].fit(commands)

    def score(self, command_line, user_type):
        """
        Score based on user context
        """
        model = self.models.get(user_type)
        tfidf = model.transform(command_line)

        # High score = rare for this user type
        return max(tfidf.values()) if tfidf else 0

# Usage
logs = {
    'admin_user': ['net user', 'psexec', 'sc query'],  # Normal for admins
    'regular_user': ['chrome.exe', 'outlook.exe', 'word.exe']
}

clf = CommandLineTFIDF()
clf.fit(logs)

# Test: Regular user running 'net user' (rare for them!)
score = clf.score('net user /domain', 'regular_user')  # High score!
```

---

## 3. Graph Theory for HopGraph

### Foundational Reading (Week 1)
- **Book**: *Introduction to Graph Theory* by Douglas West
  - Chapters 1-3: Graphs, paths, connectivity
- **Book**: *Network Science* by Albert-László Barabási
  - Chapter 2: "Graph Theory" (free online)
- **Paper**: "Provenance-based Security for Cyber-Physical Systems" (DARPA TC)

### Hands-On (Week 2)
```python
# Exercise 1: Implement graph algorithms from scratch
import networkx as nx

# Build attack graph
G = nx.DiGraph()
edges = [
    ('attacker', 'workstation', {'weight': 0.8}),
    ('workstation', 'dc', {'weight': 0.9}),
    ('dc', 'file_server', {'weight': 0.7}),
    ('file_server', 'internet', {'weight': 0.95})
]
G.add_edges_from(edges)

# Exercise 2a: Shortest path
path = nx.shortest_path(G, 'attacker', 'internet')
print(f"Attack path: {' → '.join(path)}")

# Exercise 2b: Betweenness centrality (find pivots)
centrality = nx.betweenness_centrality(G)
pivot = max(centrality, key=centrality.get)
print(f"Critical pivot: {pivot}")

# Exercise 2c: Community detection
communities = nx.community.greedy_modularity_communities(G.to_undirected())
print(f"Attack clusters: {list(communities)}")

# Exercise 3: Temporal graphs (add timestamps)
class TemporalGraph:
    def __init__(self):
        self.snapshots = []  # List of (timestamp, graph)

    def add_edge(self, timestamp, src, dst, **attrs):
        # Find or create snapshot at this time
        snapshot = self.get_or_create_snapshot(timestamp)
        snapshot.add_edge(src, dst, **attrs)

    def get_attack_path_at_time(self, timestamp, source, target):
        snapshot = self.get_snapshot(timestamp)
        return nx.shortest_path(snapshot, source, target)
```

### Production Systems to Study (Week 3)
- **Google Chronicle**: UDM (Unified Data Model) graph
  - Read: "Chronicle Security Analytics" whitepaper
- **Neo4j**: Property graph database
  - Tutorial: https://neo4j.com/developer/cypher-query-language/
- **AWS Detective**: Graph-based investigation
  - Read: https://docs.aws.amazon.com/detective/

### Advanced Implementation (Week 4)
**Project**: Temporal graph with decay
```python
class DecayingHopGraph:
    """
    Edges decay over time - recent connections weighted higher
    """
    def __init__(self, alpha=0.3):
        self.G = nx.DiGraph()
        self.alpha = alpha

    def add_event(self, event, timestamp):
        weight = self.calculate_weight(timestamp)
        self.G.add_edge(
            event.source,
            event.destination,
            weight=weight,
            timestamp=timestamp
        )

    def calculate_weight(self, timestamp):
        age_minutes = (now - timestamp).total_seconds() / 60
        return math.exp(-self.alpha * age_minutes)

    def get_weighted_paths(self, source, target):
        """
        Find paths, weight by edge freshness
        """
        paths = nx.all_simple_paths(self.G, source, target)
        weighted = []

        for path in paths:
            path_weight = 1.0
            for i in range(len(path) - 1):
                edge_data = self.G[path[i]][path[i+1]]
                path_weight *= edge_data['weight']
            weighted.append((path, path_weight))

        return sorted(weighted, key=lambda x: x[1], reverse=True)
```

---

## 4. FinOps for Cloud Optimization

### Foundational Reading (Week 1)
- **Book**: *Cloud FinOps* by J.R. Storment & Mike Fuller
  - Chapter 5: "Optimization strategies"
- **Website**: FinOps Foundation - https://www.finops.org/
  - Read: FinOps Framework documentation
- **Paper**: "A Berkeley View of Cloud Computing" (Armbrust et al., 2010)

### Hands-On (Week 2)
```python
# Exercise 1: Build cost optimizer
class AIcostOptimizer:
    def __init__(self, budget_per_day=10.0):
        self.budget = budget_per_day
        self.spent_today = 0.0
        self.ml_cost_per_event = 0.003
        self.rule_cost = 0.0

    def should_use_ml(self, event_complexity, current_hour):
        """
        Decide: cheap rules or expensive ML?
        """
        # Strategy 1: Complexity-based
        if event_complexity < 0.3:  # Simple event
            return False  # Use rules

        # Strategy 2: Budget-aware
        if self.spent_today + self.ml_cost_per_event > self.budget:
            return False  # Budget exhausted

        # Strategy 3: Time-based (expensive ML during off-hours)
        if 0 <= current_hour < 6:  # 12am-6am, low traffic
            return True  # Can afford ML

        return event_complexity > 0.7  # Only for complex events

    def track_cost(self, used_ml):
        cost = self.ml_cost_per_event if used_ml else 0
        self.spent_today += cost
        return cost

# Exercise 2: Simulate day of events
optimizer = AIcostOptimizer(budget_per_day=10.0)
events = [random.random() for _ in range(10000)]  # Random complexity

total_cost = 0
ml_count = 0

for hour in range(24):
    hour_events = events[hour*400:(hour+1)*400]  # 400 events/hour
    for event_complexity in hour_events:
        use_ml = optimizer.should_use_ml(event_complexity, hour)
        cost = optimizer.track_cost(use_ml)
        total_cost += cost
        ml_count += use_ml

print(f"Total cost: ${total_cost:.2f}")
print(f"ML events: {ml_count} ({ml_count/10000*100:.1f}%)")
print(f"Savings vs all-ML: ${10000*0.003 - total_cost:.2f}")
```

### Production Systems to Study (Week 3)
- **Databricks**: Auto-scaling and spot instances
  - Read: https://docs.databricks.com/optimizations/auto-scaling.html
- **AWS Lambda**: Pay-per-invocation model
  - Study: Cold start optimization techniques
- **Datadog**: Adaptive sampling for APM
  - Read: Ingestion controls documentation

### Advanced Implementation (Week 4)
**Project**: Reinforcement learning for routing
```python
# Use Q-learning to learn optimal fast/slow routing policy
class RLCostOptimizer:
    def __init__(self):
        self.q_table = {}  # State → Action → Q-value
        self.epsilon = 0.1  # Exploration rate
        self.alpha = 0.1  # Learning rate
        self.gamma = 0.9  # Discount factor

    def get_state(self, event):
        """
        State = (factor_count, time_of_day, budget_remaining)
        """
        return (
            min(event.factor_count, 10),  # Discretize
            event.timestamp.hour // 6,  # 4 time buckets
            int(self.budget_remaining / 2)  # Discretize budget
        )

    def choose_action(self, state):
        """
        Action = 'fast_path' or 'slow_path'
        """
        if random.random() < self.epsilon:
            return random.choice(['fast', 'slow'])  # Explore

        # Exploit: Choose best action
        q_values = self.q_table.get(state, {'fast': 0, 'slow': 0})
        return max(q_values, key=q_values.get)

    def update_q(self, state, action, reward, next_state):
        """
        Q-learning update
        """
        old_q = self.q_table.get(state, {}).get(action, 0)
        next_max = max(self.q_table.get(next_state, {'fast': 0, 'slow': 0}).values())

        new_q = old_q + self.alpha * (reward + self.gamma * next_max - old_q)

        if state not in self.q_table:
            self.q_table[state] = {}
        self.q_table[state][action] = new_q

# Reward function
def calculate_reward(action, event_was_malicious, cost):
    if action == 'fast' and event_was_malicious:
        return -10  # Missed threat (bad!)
    elif action == 'slow' and not event_was_malicious:
        return -cost * 1000  # Wasted money on benign event
    elif action == 'slow' and event_was_malicious:
        return 10 - cost * 1000  # Caught threat, worth the cost
    else:  # fast + benign
        return 1  # Saved money, correct decision
```

---

## 5. Multi-Factor Correlation

### Foundational Reading (Week 1)
- **Paper**: "Alert Correlation in Intrusion Detection Systems" (Valeur et al., 2004)
- **Paper**: "Multi-Sensor Data Fusion for Threat Detection" (Steinberg & Bowman, 2004)
- **Book**: *Data Fusion: Concepts and Ideas* by Jitendra Liggins

### Hands-On (Week 2)
```python
# Exercise: Implement Dempster-Shafer theory for factor fusion
class DempsterShafer:
    """
    Combine evidence from multiple factors with uncertainty
    """
    def __init__(self):
        self.factors = {}

    def add_evidence(self, factor_name, belief_malicious, belief_benign):
        """
        belief_malicious + belief_benign + uncertainty = 1.0
        """
        uncertainty = 1.0 - belief_malicious - belief_benign
        self.factors[factor_name] = {
            'malicious': belief_malicious,
            'benign': belief_benign,
            'uncertain': uncertainty
        }

    def combine(self):
        """
        Dempster's rule of combination
        """
        # Start with first factor
        factors = list(self.factors.values())
        combined = factors[0]

        for factor in factors[1:]:
            combined = self.dempster_combine(combined, factor)

        return combined

    def dempster_combine(self, m1, m2):
        """
        Combine two mass functions
        """
        # Conflict
        k = m1['malicious'] * m2['benign'] + m1['benign'] * m2['malicious']

        # Combined beliefs
        mal = (m1['malicious'] * m2['malicious'] +
               m1['malicious'] * m2['uncertain'] +
               m1['uncertain'] * m2['malicious']) / (1 - k)

        ben = (m1['benign'] * m2['benign'] +
               m1['benign'] * m2['uncertain'] +
               m1['uncertain'] * m2['benign']) / (1 - k)

        unc = (m1['uncertain'] * m2['uncertain']) / (1 - k)

        return {'malicious': mal, 'benign': ben, 'uncertain': unc}

# Test
ds = DempsterShafer()
ds.add_evidence('suspicious_process', belief_malicious=0.6, belief_benign=0.1)
ds.add_evidence('rare_tokens', belief_malicious=0.7, belief_benign=0.05)
ds.add_evidence('lateral_movement', belief_malicious=0.85, belief_benign=0.02)

result = ds.combine()
print(f"Combined belief: Malicious={result['malicious']:.2f}, Benign={result['benign']:.2f}")
```

### Production Systems to Study (Week 3)
- **Splunk Enterprise Security**: Correlation searches
  - Read: https://docs.splunk.com/Documentation/ES/latest/User/Correlation
- **IBM QRadar**: Offense correlation
  - Study: How multiple events become one "offense"
- **Microsoft Sentinel**: Fusion alerts
  - Read: https://docs.microsoft.com/en-us/azure/sentinel/fusion

---

# Security-Specific Learning

## Threat Hunting

### Must-Read Books
1. **"The Practice of Network Security Monitoring"** by Richard Bejtlich
2. **"Applied Network Security Monitoring"** by Chris Sanders & Jason Smith
3. **"Threat Hunting with Elastic Stack"** by Andrew Pease

### Must-Do Labs
- **TryHackMe**: https://tryhackme.com/
  - Rooms: "Cyber Defense", "Threat Hunting", "MITRE"
- **LetsDefend**: https://letsdefend.io/
  - SOC Analyst path
- **Splunk Boss of the SOC**: Annual CTF, available year-round
  - Practice dataset analysis

### Must-Watch Talks
- **"Threat Hunting: Open Season on the Adversary"** (SANS Summit 2016)
- **"Practical Threat Hunting"** (BSides talks)

---

## MITRE ATT&CK

### Official Resources
- **ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/
  - Map your detections to techniques
- **ATT&CK Training**: Free course at https://attack.mitre.org/resources/training/
- **Atomic Red Team**: https://github.com/redcanaryco/atomic-red-team
  - Test detection rules with real TTPs

### Hands-On Project
**Goal**: Build ATT&CK coverage matrix for your platform

```python
# Map every factor in your platform to MITRE techniques
FACTOR_TO_MITRE = {
    'suspicious_process': ['T1059'],  # Command and Scripting
    'suspicious_parent': ['T1059'],
    'encoded_command': ['T1027'],  # Obfuscated Files/Info
    'lateral_movement': ['T1021'],  # Remote Services
    'credential_access': ['T1003'],  # OS Credential Dumping
    'priv_escalation': ['T1548'],  # Abuse Elevation Control
    'data_exfil': ['T1041'],  # Exfiltration Over C2
    # ... map all 100 factors
}

# Generate coverage report
def generate_coverage_matrix():
    """
    Show which MITRE techniques you can detect
    """
    all_techniques = set()
    for techniques in FACTOR_TO_MITRE.values():
        all_techniques.update(techniques)

    print(f"Total techniques covered: {len(all_techniques)}")
    print(f"Techniques: {sorted(all_techniques)}")

    # Compare to full ATT&CK matrix (use mitreattack-python library)
    # Calculate coverage percentage
```

---

# Interview Prep Timeline

## Week 1-2: Memorize Core Concepts
- Practice explaining EWMA, TF-IDF, HopGraph, Multi-factor correlation
- Time yourself: 2-minute explanations
- Record yourself, watch back, improve

## Week 3-4: Build Demo Muscle Memory
- Run through all 5 demos 10 times each
- Practice transitions between demos
- Prepare for "what if" questions

## Week 5-6: Mock Interviews
- Technical: Whiteboard architecture, code reviews
- Non-Technical: Business value, ROI calculations
- Get feedback, iterate

## Week 7-8: Deepen One Area
Pick your favorite:
- Go deep on ML/AI side (EWMA, TF-IDF, embeddings)
- Go deep on security side (MITRE, threat hunting, TTPs)
- Go deep on engineering side (distributed systems, graph databases)

Become the expert in that one area. This is your "superpower" in interviews.

---

# Final Advice

**You don't need to know everything.**

But you DO need to:
1. ✅ Understand the fundamentals (EWMA math, TF-IDF concept, graph theory basics)
2. ✅ Explain design decisions (why EWMA not SMA, why TF-IDF for rare tokens)
3. ✅ Know where to learn more (point to papers, systems, techniques)
4. ✅ Demonstrate curiosity (talk about what you'd do differently, future enhancements)

**The best answer to "I don't know"**:
> "I haven't implemented that yet, but here's how I'd approach it based on [similar technique]. I'd start by reading [specific paper/blog], then test with [specific dataset]. Want me to prototype it?"

This shows: humility + structured thinking + willingness to learn.

**Now go master these concepts. You've got this!** 🚀
