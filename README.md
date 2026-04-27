# RIZZ 🔥
## API Security Testing Suite for Burp

> Your API vuln scanner has **RIZZ** (charisma to find every weakness)

---

## What is RIZZ?

RIZZ is a **unified Burp extension** that combines 3 powerful security analysis tools into ONE sleek tab:

✅ **Response Analyzer** - Finds exposed data (IDs, emails, tokens)  
✅ **Hidden Field Detector** - Discovers admin fields & generates payloads  
✅ **Response Diff Analyzer** - Catches authorization bypasses  

**One tab. Three superpowers. Maximum chaos.**

---

## Why RIZZ?

Because this tool has **RIZZ** — it finds API vulnerabilities with style:
-  Finds what others miss
-  No cap (seriously finds real bugs)
-  Fast, sleek, Gen Z approved
-  Built for bug bounty hunters

---

## Installation

### 30 Second Setup
```bash
# 1. Get the file
# RIZZ.py

# 2. Load into Burp
Burp → Extensions → Installed → Add
Language: Python
File: RIZZ.py

# 3. Test
Intercept any JSON API response → See "RIZZ" tab appear
```

---

## UI: 4 Tabs of Power

```
┌─────────────────────────────────────────┐
│  RIZZ Extension                         │
├─────────────────────────────────────────┤
│ [Response Analyzer] [Hidden Fields]     │
│ [Response Diff]     [Raw Response]      │
├─────────────────────────────────────────┤
│                                         │
│  [Analyze Response] [Detect Fields]     │
│  [Store Response]   [Compare]           │
│                                         │
└─────────────────────────────────────────┘
```

---

## 3 Ways to Find Bugs

### 1️⃣ Response Analyzer
**Find exposed data**

Click: `[Analyze Response]`

```
[RISK] userId -> int          ← IDOR target
[RISK] internalId -> 54892    ← Enumeration target
[!] email: user@example.com   ← Data leak
[!] token: sk_live_...        ← Token exposure
```

**Bounty**: $200-1000 per finding

---

### 2️⃣ Hidden Field Detector
**Discover admin fields & generate payloads**

Click: `[Detect Hidden Fields]` → `[Generate Exploits]`

Finds:
- `__schema` → GraphQL introspection enabled
- `isAdmin` → Privilege escalation
- `_debug` → Debug mode active
- `internalApiKey` → API key exposure

Auto-generates payloads:
```graphql
mutation { updateUser(id: 1, isAdmin: true) { id isAdmin } }
query { __schema { types { name } } }
{ a1: user(id:1) { id } a2: user(id:2) { id } ... }
```

**Bounty**: $500-3000 per finding

---

### 3️⃣ Response Diff Analyzer
**Catch authorization bypasses**

Workflow:
```
1. Store authenticated response
2. Remove auth header
3. Replay request
4. Click [Compare & Analyze]
5. See what changed → Find bypass!
```

Auto-detects:
- ✗ Complete authorization bypass
- ✗ User data without auth
- ✗ Admin fields visible
- ✗ Sensitive fields exposed

**Bounty**: $1000-5000+ (CRITICAL)

---

## Pro Tips

### Tip 1: Test Everything
- Don't skip any API response
- Run RIZZ on every new endpoint
- Compare different user profiles
- Test with/without auth

### Tip 2: Copy-Paste Payloads
- Hidden Field Detector generates ready-to-use payloads
- Paste straight into Burp Repeater
- Test immediately
- Document what works

### Tip 3: Response Diff is King
- Most critical bugs are auth-related
- Use Response Diff on every sensitive endpoint
- Compare: with auth vs without auth
- Compare: user 1 vs user 2
- Most valuable finding type

### Tip 4: Payload Customization
- Edit generated payloads in "Mutation Payloads" tab
- Create custom mutation attempts
- Build library of working payloads
- Reuse across similar targets

---


## Troubleshooting

| Issue | Fix |
|-------|-----|
| Tab not appearing | Response must be valid JSON (check Content-Type) |
| No findings detected | Try different endpoints or auth states |
| Payload generation failed | Run "Detect Hidden Fields" first, then "Generate Exploits" |
| Extension won't load | Check Burp Extensions → Output for error message |

---


## Next Steps

1. ✅ Load RIZZ into Burp
2. ✅ Test with any public GraphQL API
3. ✅ Familiarize yourself with all 3 tabs
4. ✅ Start on bug bounty program targets
5. ✅ Document findings
6. ✅ Submit reports
7. ✅ Collect bounty 💰

---


## The Philosophy

RIZZ isn't just a tool — it's a **workflow optimization**:
- One tab instead of three
- No context switching
- Zero friction from idea to finding
- Built for speed and chaos

---


**No cap. This tool has RIZZ.**
