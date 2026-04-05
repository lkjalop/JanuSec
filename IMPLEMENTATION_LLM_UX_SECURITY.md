# LLM Provider UX & Security Implementation Guide

## Overview
This document outlines the implementation of user-friendly LLM provider selection with enterprise-grade security for API keys.

## Security Requirements

### 1. API Key Protection
- ✅ **Never store in LocalStorage** (XSS vulnerable)
- ✅ **Encrypt at rest** using Fernet (symmetric encryption)
- ✅ **Mask in UI** (show only last 4 characters)
- ✅ **Server-side only** (never send full keys to frontend)
- ✅ **Audit logging** (who configured what, when)
- ✅ **IP restrictions** (optional whitelist for API access)
- ✅ **Rate limiting** (prevent key abuse)

### 2. Threat Model
**Attack Vectors We're Protecting Against:**
- XSS attacks stealing keys from LocalStorage
- Man-in-the-middle attacks (enforced HTTPS in production)
- Insider threats (audit logging)
- Credential stuffing (rate limiting)
- Database dumps (encryption at rest)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (Browser)                    │
│  ┌──────────────────────────────────────────────────┐  │
│  │  CSV Analyzer / Deep Analyze Pages               │  │
│  │  - Provider dropdown (Ollama/OpenAI/Claude/None) │  │
│  │  - Status indicator (⚡ Ollama Ready)            │  │
│  │  - API key input (masked: sk-...abc123)          │  │
│  └──────────────────┬───────────────────────────────┘  │
└─────────────────────┼───────────────────────────────────┘
                      │ HTTPS Only
                      │ (enforced in production)
┌─────────────────────▼───────────────────────────────────┐
│                Backend (FastAPI)                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  /api/v1/config/llm                              │  │
│  │  - GET: health status (no secrets)               │  │
│  │  - POST: save config (encrypt keys)              │  │
│  │  - PUT: update provider                          │  │
│  └──────────────────┬───────────────────────────────┘  │
│                     │                                    │
│  ┌──────────────────▼───────────────────────────────┐  │
│  │  Security Layer                                   │  │
│  │  - Fernet encryption/decryption                  │  │
│  │  - Audit logging                                 │  │
│  │  - Rate limiting (10 req/min per IP)            │  │
│  └──────────────────┬───────────────────────────────┘  │
└─────────────────────┼───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│                  Storage (Encrypted)                     │
│  SQLite/Neon PostgreSQL                                 │
│  ┌──────────────────────────────────────────────────┐  │
│  │  llm_config table:                                │  │
│  │  - provider_type (text)                          │  │
│  │  - encrypted_api_key (blob)  ← Fernet encrypted │  │
│  │  - ollama_host (text)                            │  │
│  │  - model_name (text)                             │  │
│  │  - created_at, updated_at                        │  │
│  │  - created_by (audit)                            │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Implementation Steps

### Phase 1: Backend Security (CRITICAL - DO FIRST)

#### 1.1 Create Encryption Module
```python
# src/security/key_encryption.py
from cryptography.fernet import Fernet
import os
import base64
from pathlib import Path

class KeyVault:
    """Secure storage for API keys using Fernet encryption."""

    def __init__(self):
        # Load or generate encryption key
        key_file = Path("data/encryption.key")
        if key_file.exists():
            self.key = key_file.read_bytes()
        else:
            self.key = Fernet.generate_key()
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_bytes(self.key)
            key_file.chmod(0o600)  # Owner read/write only

        self.cipher = Fernet(self.key)

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt an API key."""
        return self.cipher.encrypt(plaintext.encode())

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt an API key."""
        return self.cipher.decrypt(ciphertext).decode()

    @staticmethod
    def mask_key(api_key: str) -> str:
        """Mask API key for display (show only last 4 chars)."""
        if not api_key or len(api_key) < 8:
            return "****"
        return f"{api_key[:3]}...{api_key[-4:]}"
```

#### 1.2 Create Audit Logger
```python
# src/security/audit_log.py
import logging
from datetime import datetime
from typing import Optional

audit_logger = logging.getLogger('security.audit')

class AuditLog:
    @staticmethod
    def log_llm_config_change(
        action: str,  # 'create', 'update', 'delete'
        provider: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        audit_logger.info(
            f"LLM_CONFIG_CHANGE: action={action} provider={provider} "
            f"user={user_id or 'unknown'} ip={ip_address or 'unknown'} "
            f"timestamp={datetime.utcnow().isoformat()}"
        )
```

#### 1.3 Update LLM Config Endpoint with Security
```python
# src/api/llm_config_secure.py
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional
from src.security.key_encryption import KeyVault, mask_key
from src.security.audit_log import AuditLog
from src.security.auth import require_scopes
import re

router = APIRouter()
vault = KeyVault()

class LLMConfigRequest(BaseModel):
    provider: str = Field(..., pattern="^(ollama|openai|anthropic|none)$")
    api_key: Optional[str] = None  # Only for openai/anthropic
    ollama_host: Optional[str] = None
    model_name: Optional[str] = None

class LLMConfigResponse(BaseModel):
    provider: str
    masked_api_key: Optional[str] = None
    ollama_host: Optional[str] = None
    model_name: Optional[str] = None
    status: str  # 'configured', 'testing', 'error'

@router.get('/api/v1/config/llm', response_model=LLMConfigResponse)
async def get_llm_config(auth: dict = Depends(require_scopes(['read:config']))):
    """Get current LLM configuration (with masked API keys)."""
    # Load from database
    config = load_llm_config()  # Your DB loader

    # Mask API key if present
    if config.get('api_key_encrypted'):
        config['masked_api_key'] = KeyVault.mask_key('sk-xxxxx')  # Don't decrypt for GET

    return LLMConfigResponse(
        provider=config.get('provider', 'none'),
        masked_api_key=config.get('masked_api_key'),
        ollama_host=config.get('ollama_host'),
        model_name=config.get('model_name'),
        status=config.get('status', 'not_configured')
    )

@router.post('/api/v1/config/llm')
async def save_llm_config(
    request: Request,
    payload: LLMConfigRequest,
    auth: dict = Depends(require_scopes(['write:config']))
):
    """Save LLM configuration with encrypted API keys."""
    ip = request.client.host
    user_id = auth.get('user_id', 'unknown')

    # Validate API key format
    if payload.provider in ['openai', 'anthropic']:
        if not payload.api_key:
            raise HTTPException(400, "API key required for this provider")

        # Basic format validation
        if payload.provider == 'openai' and not payload.api_key.startswith('sk-'):
            raise HTTPException(400, "Invalid OpenAI API key format")

        # Encrypt the key
        encrypted_key = vault.encrypt(payload.api_key)
    else:
        encrypted_key = None

    # Save to database
    save_llm_config_to_db({
        'provider': payload.provider,
        'api_key_encrypted': encrypted_key,
        'ollama_host': payload.ollama_host,
        'model_name': payload.model_name,
        'updated_by': user_id,
        'updated_from_ip': ip
    })

    # Audit log
    AuditLog.log_llm_config_change(
        action='update',
        provider=payload.provider,
        user_id=user_id,
        ip_address=ip
    )

    return {"ok": True, "provider": payload.provider}

@router.post('/api/v1/config/llm/test')
async def test_llm_connection(
    provider: str,
    auth: dict = Depends(require_scopes(['write:config']))
):
    """Test LLM provider connection."""
    config = load_llm_config()

    if provider == 'ollama':
        # Test Ollama
        import httpx
        try:
            resp = httpx.get(f"{config['ollama_host']}/api/tags", timeout=5)
            return {"status": "ok", "provider": "ollama"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    elif provider in ['openai', 'anthropic']:
        # Decrypt key and test
        decrypted_key = vault.decrypt(config['api_key_encrypted'])
        # ... test API connection ...
        return {"status": "ok", "provider": provider}
```

### Phase 2: Frontend Components

#### 2.1 Add AI Settings Link to Sidebar
```html
<!-- Add to janusec-platform-live.html after line 673 (in System section) -->
<div class="nav-item" onclick="window.open('/static/ai_settings.html','_blank')">
    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
    </svg>
    AI Providers
</div>
```

#### 2.2 Create LLM Status Component (for CSV Analyzer)
```javascript
// frontend/static/js/llm_status.js
class LLMStatusManager {
    constructor() {
        this.currentProvider = 'none';
        this.health = {};
    }

    async checkHealth() {
        try {
            const resp = await fetch('/api/v1/config/llm', {
                headers: {'x-api-key': localStorage.getItem('apiKey') || 'devkey123'}
            });
            const data = await resp.json();
            this.currentProvider = data.provider;
            this.health = data;
            this.updateUI();
            return data;
        } catch (e) {
            console.error('LLM health check failed:', e);
            this.showError();
        }
    }

    updateUI() {
        const indicator = document.getElementById('llmStatusIndicator');
        if (!indicator) return;

        const icons = {
            'ollama': '⚡',
            'openai': '🤖',
            'anthropic': '🧠',
            'none': '⚠️'
        };

        const labels = {
            'ollama': 'Ollama (Local)',
            'openai': 'OpenAI',
            'anthropic': 'Claude',
            'none': 'Not Configured'
        };

        indicator.innerHTML = `
            <span class="llm-status-icon">${icons[this.currentProvider]}</span>
            <span class="llm-status-label">${labels[this.currentProvider]}</span>
        `;

        indicator.className = this.currentProvider === 'none' ?
            'llm-status warning' : 'llm-status ok';
    }

    async promptConfiguration() {
        const modal = document.createElement('div');
        modal.id = 'llmConfigModal';
        modal.innerHTML = `
            <div class="modal-overlay">
                <div class="modal-content">
                    <h2>🤖 Configure AI Provider</h2>
                    <p>No LLM provider is currently configured. Choose one to enable AI-powered analysis:</p>

                    <div class="provider-options">
                        <div class="provider-card">
                            <h3>⚡ Ollama (Recommended)</h3>
                            <p>Free • Private • Runs locally</p>
                            <button onclick="window.open('/static/ai_settings.html')">
                                Configure Ollama
                            </button>
                        </div>

                        <div class="provider-card">
                            <h3>🤖 OpenAI</h3>
                            <p>Cloud API • Costs apply</p>
                            <button onclick="window.open('/static/ai_settings.html')">
                                Configure OpenAI
                            </button>
                        </div>

                        <div class="provider-card">
                            <h3>🧠 Claude</h3>
                            <p>Cloud API • Costs apply</p>
                            <button onclick="window.open('/static/ai_settings.html')">
                                Configure Claude
                            </button>
                        </div>
                    </div>

                    <button class="btn-secondary" onclick="this.closest('.modal-overlay').remove()">
                        Skip for Now
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    async ensureConfigured() {
        const health = await this.checkHealth();
        if (health.provider === 'none') {
            await this.promptConfiguration();
            return false;
        }
        return true;
    }
}

// Global instance
window.llmStatus = new LLMStatusManager();
```

#### 2.3 Update CSV Analyzer with LLM Integration
```html
<!-- Add to csv_analyzer.html header -->
<div class="llm-status-bar">
    <div id="llmStatusIndicator" class="llm-status">
        <span class="llm-status-icon">⚙️</span>
        <span class="llm-status-label">Checking...</span>
    </div>

    <select id="llmProviderOverride" class="llm-provider-select">
        <option value="auto">Auto (use default)</option>
        <option value="ollama">⚡ Ollama (local)</option>
        <option value="openai">🤖 OpenAI</option>
        <option value="anthropic">🧠 Claude</option>
        <option value="none">Disable LLM</option>
    </select>
</div>

<script src="/static/js/llm_status.js"></script>
<script>
// Check LLM status on page load
document.addEventListener('DOMContentLoaded', async () => {
    await window.llmStatus.checkHealth();
});

// Pre-flight check before Tier 1 analysis
async function generateTier1Summary(row) {
    // Check if LLM is configured
    const isConfigured = await window.llmStatus.ensureConfigured();
    if (!isConfigured) {
        return; // User canceled or needs to configure
    }

    // Get provider override if selected
    const override = document.getElementById('llmProviderOverride').value;
    const provider = override === 'auto' ? null : override;

    // Make API call
    const resp = await fetch('/api/v1/insights/generate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': localStorage.getItem('apiKey') || 'devkey123'
        },
        body: JSON.stringify({
            row: row,
            insight_type: 'tier1',
            provider_override: provider
        })
    });

    const result = await resp.json();
    // Display result...
}
</script>
```

### Phase 3: CSS Styling
```css
/* Add to theme.css or csv_analyzer.html */
.llm-status-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 12px;
}

.llm-status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
}

.llm-status.ok {
    color: var(--success);
}

.llm-status.warning {
    color: var(--warning);
}

.llm-provider-select {
    padding: 6px 12px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-size: 12px;
}

.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
}

.modal-content {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    max-width: 600px;
    width: 90%;
}

.provider-options {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin: 20px 0;
}

.provider-card {
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}

.provider-card h3 {
    margin: 0 0 8px;
    font-size: 16px;
}

.provider-card p {
    font-size: 12px;
    color: var(--text-muted);
    margin: 0 0 12px;
}
```

## Security Checklist

- [ ] Encryption key stored in `data/encryption.key` with 0600 permissions
- [ ] API keys encrypted before database storage
- [ ] API keys never sent to frontend (masked only)
- [ ] Audit logging for all config changes
- [ ] Rate limiting on config endpoints (10/min)
- [ ] HTTPS enforced in production
- [ ] API key format validation
- [ ] Test connection before saving
- [ ] User authentication required for config changes
- [ ] Database backups exclude encryption keys

## Testing Plan

1. **Security Testing:**
   - [ ] Verify encryption key is generated securely
   - [ ] Verify API keys are encrypted in database
   - [ ] Verify masked keys shown in UI
   - [ ] Verify audit logs capture changes
   - [ ] Test rate limiting

2. **UX Testing:**
   - [ ] Test status indicator shows correct provider
   - [ ] Test modal appears when no provider configured
   - [ ] Test provider dropdown allows override
   - [ ] Test navigation link opens AI settings
   - [ ] Test configuration flow end-to-end

3. **Integration Testing:**
   - [ ] Test Ollama connection
   - [ ] Test OpenAI API call
   - [ ] Test Claude API call
   - [ ] Test fallback when provider fails

## Deployment Notes

**Production Requirements:**
1. Set `FERNET_KEY` environment variable (don't use auto-generated)
2. Enable HTTPS only (no HTTP)
3. Configure proper CORS policies
4. Set up database backups (exclude encryption keys)
5. Monitor audit logs for suspicious activity
6. Implement IP whitelisting if needed

**Environment Variables:**
```bash
# Required for production
FERNET_KEY=<base64-encoded-32-byte-key>
ENFORCE_HTTPS=true
ALLOWED_ORIGINS=https://yourdomain.com
RATE_LIMIT_ENABLED=true
AUDIT_LOG_PATH=/var/log/janusec/audit.log
```

## FAQ

**Q: What happens if the encryption key is lost?**
A: All encrypted API keys become unrecoverable. Users must reconfigure providers. This is by design for security.

**Q: Can users switch providers per-analysis?**
A: Yes! The dropdown allows per-session override while keeping the default configured.

**Q: How do we handle costs for cloud APIs?**
A: The AI Settings page includes budget limits. When exceeded, the system can auto-fallback to Ollama.

**Q: Is Ollama truly free?**
A: Yes, but requires local GPU/CPU resources. It's "free" as in no API costs, but hardware costs apply.

## Next Steps

1. Implement Phase 1 (Backend Security) - CRITICAL
2. Test encryption/decryption flow
3. Implement Phase 2 (Frontend Components)
4. Add to platform navigation
5. Test end-to-end
6. Deploy with proper production config
