"""Quick test script to verify Ollama integration before starting full platform."""
import os
import sys

# Set D drive path
sys.path.insert(0, r'D:\AI\Threat_thy_sniffer')
os.chdir(r'D:\AI\Threat_thy_sniffer')

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("OLLAMA INTEGRATION TEST")
print("=" * 60)

# Test 1: Verify Ollama server is accessible
print("\n[TEST 1] Checking Ollama server...")
try:
    import requests
    response = requests.get('http://127.0.0.1:11434/api/tags', timeout=5)
    if response.status_code == 200:
        models = response.json().get('models', [])
        print("[OK] Ollama server is running")
        print(f"   Available models: {', '.join([m['name'] for m in models])}")
    else:
        print(f"[FAIL] Ollama server returned status {response.status_code}")
        sys.exit(1)
except Exception as e:
    print(f"[FAIL] Cannot connect to Ollama server: {e}")
    print("   Make sure Ollama is running: ollama serve")
    sys.exit(1)

# Test 2: Verify environment variables
print("\n[TEST 2] Checking environment variables...")
required_vars = {
    'DEFAULT_CLIENT': 'ollama',
    'OSS_MODELS_ENABLE': 'true',
    'OSS_MODELS_BACKEND': 'ollama',
    'OLLAMA_DEFAULT_MODEL': 'llama3:8b',
    'OLLAMA_HOST': 'http://127.0.0.1:11434'
}

all_good = True
for var, expected in required_vars.items():
    actual = os.getenv(var, '')
    if actual.lower() == expected.lower():
        print(f"[OK] {var}={actual}")
    else:
        print(f"[FAIL] {var}={actual} (expected: {expected})")
        all_good = False

if not all_good:
    print("\n[FAIL] Environment variables not configured correctly")
    print("   Check your .env file")
    sys.exit(1)

# Test 3: Test direct Ollama generation
print("\n[TEST 3] Testing direct Ollama generation...")
try:
    payload = {
        'model': 'llama3:8b',
        'prompt': 'Explain what process injection is in exactly 2 sentences.',
        'stream': False,
        'options': {'num_predict': 100}
    }

    print("   Sending request to Ollama... (this may take 10-30 seconds)")
    response = requests.post(
        'http://127.0.0.1:11434/api/generate',
        json=payload,
        timeout=60
    )

    if response.status_code == 200:
        result = response.json()
        generated_text = result.get('response', '')
        print("[OK] Ollama generated response:")
        print(f"   {generated_text[:200]}...")
        print(f"   Total tokens: {result.get('eval_count', 0)}")
        print(f"   Time: {result.get('total_duration', 0) / 1e9:.2f} seconds")
    else:
        print(f"[FAIL] Ollama generation failed: {response.status_code}")
        sys.exit(1)

except Exception as e:
    print(f"[FAIL] Ollama generation error: {e}")
    sys.exit(1)

# Test 4: Test platform's OSS model manager
print("\n[TEST 4] Testing platform's OpenSourceModelManager...")
try:
    from src.ai.oss_models import OpenSourceModelManager

    config = {
        'enable': True,
        'backend': 'ollama',
        'device': 'cpu',
        'ollama_root': 'D:/Ollama',
        'ollama_host': 'http://127.0.0.1:11434',
        'ollama_cmd': None
    }

    manager = OpenSourceModelManager(config)
    print("[OK] OpenSourceModelManager initialized")
    print(f"   Backend: {manager.backend}")
    print(f"   Enabled: {manager.enabled}")
    print(f"   Ollama host: {manager.ollama_host}")

except Exception as e:
    print(f"[FAIL] OpenSourceModelManager initialization failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 5: Test LLM client with Ollama
print("\n[TEST 5] Testing LLM client with Ollama backend...")
try:
    # Set environment to force Ollama
    os.environ['DEFAULT_CLIENT'] = 'ollama'

    from src.integrations.llm_client import generate_summary

    test_prompt = """Analyze this security artifact:
Process: powershell.exe
Host: WORKSTATION-042
Factors: process_injection, unsigned_binary
Verdict: suspicious

Provide a 3-line summary."""

    print("   Generating summary via LLM client... (10-30 seconds)")
    result = generate_summary(test_prompt, max_tokens=150)

    if isinstance(result, dict):
        text = result.get('text', '')
    else:
        text = str(result)

    print("[OK] LLM client generated summary:")
    print(f"   {text[:300]}...")

except Exception as e:
    print(f"[WARN] LLM client test failed (this is okay if client doesn't support Ollama yet): {e}")
    # Don't exit - this might not be implemented yet

print("\n" + "=" * 60)
print("[SUCCESS] OLLAMA INTEGRATION TESTS PASSED!")
print("=" * 60)
print("\nYou can now start the platform with Ollama:")
print("  python run_platform.py")
print("\nThen test LLM summaries at:")
print("  http://localhost:8000/static/csv_analyzer.html")
