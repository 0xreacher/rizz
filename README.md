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

## Real World Examples

### Example 1: Instagram-like Social API
```
[RIZZ Response Analyzer]
→ Find: userId: 12345, internalId: 9999
→ Exploit: Change ID to 99999 → Get other user's data
→ Bounty: $1000 (IDOR vulnerability)

[RIZZ Hidden Field Detector]
→ Find: isAdmin: false
→ Payload: mutation { updateUser(id: 1, isAdmin: true) }
→ Bounty: $2000 (Privilege escalation)

[RIZZ Response Diff]
→ Store: Auth response
→ Remove: Authorization header
→ Compare: Same user data returned
→ Bounty: $3000 (Authorization bypass - CRITICAL)
```

**Total from one API: $6000+**

---

### Example 2: GraphQL API
```
[RIZZ Hidden Field Detector]
→ Find: __schema field present
→ Generate: Introspection query
→ Enumerate: Entire API surface (50+ queries/mutations)
→ Discover: Hidden mutation "deleteAllUsers()"
→ Bounty: $1000-2000

[RIZZ Response Analyzer]
→ Find: internalDatabaseId: "db-prod-us-east-1"
→ Impact: Infrastructure disclosure
→ Bounty: $300
```

**Total from one API: $1300-2300**

---

## Quick Workflow

### For IDOR Hunting
```
1. Intercept API with user-specific data
2. Open RIZZ → Response Analyzer
3. [Analyze Response]
4. Look for: userId, internalId, *Id fields
5. Manual test: Change ID parameter
6. Confirm IDOR
7. Submit to HackerOne
```

### For Privilege Escalation
```
1. Intercept API response
2. Open RIZZ → Hidden Field Detector
3. [Detect Hidden Fields]
4. Look for: isAdmin, role, permissions (CRITICAL risk)
5. [Generate Exploits]
6. Copy payload from "Mutation Payloads"
7. Test in Repeater
8. If it works → $1000+ bounty
```

### For Authorization Bypass
```
1. Intercept authenticated API response
2. Open RIZZ → Response Diff
3. [Store Current Response]
4. Modify request (remove auth, change ID)
5. Replay request
6. [Compare & Analyze]
7. Check "Security Issues" tab
8. If "Complete authorization bypass" → CRITICAL bounty
```

---

## Bounty Scale

| Finding | Tool | Difficulty | Bounty |
|---------|------|-----------|--------|
| IDOR (sequential ID) | Response Analyzer | ⭐ Easy | $500-2000 |
| Admin field bypass | Hidden Field Detector | ⭐⭐ Medium | $1000-3000 |
| Auth bypass | Response Diff | ⭐⭐⭐ Hard | $2000-5000+ |
| GraphQL introspection | Hidden Field Detector | ⭐ Easy | $500-1500 |
| Data exposure | Response Analyzer | ⭐ Easy | $200-1000 |
| Debug fields leaking secrets | Both | ⭐⭐ Medium | $300-1000 |

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