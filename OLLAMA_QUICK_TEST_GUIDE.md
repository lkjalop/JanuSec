# Ollama Quick Test Guide - llama3:8b on CPU

**Status:** ✅ Ollama is configured and ready to test
**Model:** llama3:8b (4.7 GB)
**Mode:** CPU (expect 30-60 seconds per summary)

---

## ⚠️ IMPORTANT: Performance Expectations

**CPU Mode Performance:**
- **First generation:** 60-90 seconds (loading model into RAM)
- **Subsequent generations:** 30-60 seconds each
- **Memory usage:** ~5 GB RAM

**This is NORMAL for CPU mode.** For faster performance, you would need a GPU.

---

## 🚀 OPTION 1: Test with Simple LLM Summary (RECOMMENDED)

### Step 1: Start the Platform

```bash
cd D:\AI\Threat_thy_sniffer
python run_platform.py
```

Wait for: `Uvicorn running on http://0.0.0.0:8000`

---

### Step 2: Warm Up Ollama (Pre-load Model)

Open a **second terminal** and run this to preload the model:

```bash
curl -X POST http://127.0.0.1:11434/api/generate -d "{\"model\": \"llama3:8b\", \"prompt\": \"Hello\", \"stream\": false}"
```

**Expected:** This will take 60-90 seconds the first time. You'll see no output for a while - this is normal!

**You'll know it's working when you see:** JSON response with "response": "Hello! ..."

---

### Step 3: Test LLM Summary via Platform

Now that the model is warmed up, test via the platform:

**Open browser:** `http://localhost:8000/static/csv_analyzer.html`

**Upload test CSV:** `tests/test_data/option_c_demo.csv`

**Wait for pipeline processing** (10-30 seconds - this is FREE, no LLM yet)

**Generate LLM Summary:**
- Option A: Click **[Investigate Further]** on any row
  - This will generate a Tier 2 deep analysis (60-147 lines)
  - **Expected time: 30-60 seconds on CPU**
  - Cost: $0 (using Ollama, no API charges)

---

### Step 4: Watch the Console for Ollama Activity

In your platform terminal, you should see logs like:

```
INFO: Using Ollama backend for LLM generation
INFO: Generating summary with llama3:8b...
```

In your browser:
- Status will show: "Generating summary... (this may take 30-60 seconds on CPU)"
- Progress indicator will spin

---

### Step 5: View Generated Summary

After 30-60 seconds, you'll see:

```
FOR: THREAT HUNTER | FORENSIC ANALYST
DOMAIN: ENDPOINT (Confidence: 0.92)

SECTION 1: WHAT IS IT? WHY SUSPICIOUS?

PowerShell execution with process injection factors detected...
[... full 60-147 line analysis ...]
```

**Cost shown:** $0.00 (local Ollama - no API charges)

---

## 🚀 OPTION 2: Test with Quick API Call

If you want to test Ollama directly without the full platform:

### Simple Test (after model is warmed up):

```bash
curl -X POST http://127.0.0.1:11434/api/generate -d "{
  \"model\": \"llama3:8b\",
  \"prompt\": \"What is process injection? Answer in 2 sentences.\",
  \"stream\": false,
  \"options\": {\"num_predict\": 50}
}"
```

**Expected time:** 30-60 seconds (CPU)
**Expected output:** JSON with "response" field containing the answer

---

## 🐛 TROUBLESHOOTING

### Issue: Request Times Out After 2 Minutes

**Cause:** Model is being loaded for the first time (4.7 GB into RAM)

**Fix:**
```bash
# Option 1: Run Ollama in separate terminal window to see logs
ollama serve

# Option 2: Pre-run the model to warm it up
ollama run llama3:8b "Hello"

# Then try the platform again
```

---

### Issue: "Connection Refused" Error

**Cause:** Ollama server not running

**Fix:**
```bash
# Check if Ollama is running
tasklist | findstr ollama

# If not running, start it
ollama serve
```

---

### Issue: Too Slow (60+ Seconds)

**This is expected on CPU.** Options to speed up:

**Option A: Use smaller/faster model**
```bash
# Pull phi3 (smaller, faster)
ollama pull phi3:mini

# Update .env
OLLAMA_DEFAULT_MODEL=phi3:mini

# Restart platform
```

**Option B: Use GPU (if you have NVIDIA GPU)**
```bash
# Check if CUDA is available
nvidia-smi

# Update .env
OSS_MODELS_DEVICE=cuda

# Restart platform
# Should be 3-8 seconds instead of 30-60
```

**Option C: Switch to Cloud API (much faster)**
```bash
# Update .env - comment out Ollama, uncomment Anthropic/OpenAI
# DEFAULT_CLIENT=anthropic
# ANTHROPIC_API_KEY=your-key-here

# Restart platform
# Will be 1-3 seconds but costs $0.003/summary
```

---

## ✅ SUCCESS CRITERIA

Ollama is working if:

1. ✅ Platform starts without errors
2. ✅ CSV uploads successfully
3. ✅ Pipeline processes all rows (10-30 sec)
4. ✅ Click "Investigate Further" → see "Generating..." status
5. ✅ After 30-60 seconds → see full summary text
6. ✅ Cost shows $0.00 (local Ollama)
7. ✅ No errors in console

---

## 📊 EXPECTED PERFORMANCE

### With llama3:8b on CPU:

| Task | Time | Cost |
|------|------|------|
| Upload CSV (10 rows) | 5 sec | Free |
| Pipeline processing | 10-30 sec | Free |
| **First LLM summary** | **60-90 sec** | **$0.00** |
| **Subsequent summaries** | **30-60 sec each** | **$0.00** |
| Generate report | 5 sec | Free |

**Total for 10-row CSV with 1 deep investigation: ~2-3 minutes**

Compare to cloud API:
- Same workflow: ~30 seconds total
- Cost: $0.003

---

## 🎯 RECOMMENDED TESTING FLOW

### For First-Time Ollama Test:

1. **Start platform:** `python run_platform.py`
2. **Warm up model:** Run simple curl command (60-90 sec wait)
3. **Open browser:** `http://localhost:8000/static/csv_analyzer.html`
4. **Upload CSV:** `tests/test_data/option_c_demo.csv`
5. **Click [Investigate Further]** on 1 row only
6. **Wait patiently:** 30-60 seconds
7. **Success:** See full summary

### For Production/Demo:

**Recommended:** Use cloud API (Anthropic Claude Haiku)
- Same accuracy
- 20x faster (1-3 sec vs 30-60 sec)
- Low cost ($0.0005 per summary)

**Reserve Ollama for:**
- Data privacy requirements (air-gapped environments)
- Development/testing without API costs
- When you have GPU acceleration

---

## 🚀 READY TO TEST?

**Start here:**

```bash
# Terminal 1: Start platform
cd D:\AI\Threat_thy_sniffer
python run_platform.py

# Terminal 2: Warm up Ollama (while platform is starting)
curl -X POST http://127.0.0.1:11434/api/generate -d "{\"model\": \"llama3:8b\", \"prompt\": \"Test\", \"stream\": false}"

# Browser: Open CSV Analyzer
http://localhost:8000/static/csv_analyzer.html

# Upload and test!
```

**Be patient - first generation takes 60-90 seconds on CPU. This is normal! ⏱️**
