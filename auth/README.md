```bash
# Example 1: Internal Provider (Password)
curl -X POST http://localhost:8080/auth \
-H "X-Auth-Method: password" \
-H "X-Auth-Credential: alice:Secret12345@" \
-H "X-Auth-Provider: internal"
```

```bash
# Example 2: Internal Provider (API Key)
curl -X POST http://localhost:8080/auth \
-H "X-Auth-Method: apikey" \
-H "X-Auth-Credential: k1:<API_KEY_PRINTED_ON_STARTUP>" \
-H "X-Auth-Provider: internal"
```

```bash
# Example 3: External Provider (Stub)
curl -X POST http://localhost:8080/auth \
-H "X-Auth-Method: any" \
-H "X-Auth-Credential: anything" \
-H "X-Auth-Provider: external"
```
