# Security Architecture Review: Jellyfin SSO Plugin v4.0.0.4

## 1. Application Overview

This is a Jellyfin media server plugin that adds Single Sign-On (SSO) authentication via OpenID Connect (OIDC) and SAML 2.0 protocols. It runs as an ASP.NET Core controller within the Jellyfin server process, exposing HTTP endpoints under `/sso/` and `/SSOViews/`.

**Key Components:**
- `SSOController` (Api/SSOController.cs) -- Main API controller handling all auth flows
- `SSOViewsController` (Views/SSOViewsController.cs) -- Serves static frontend assets
- `PluginConfiguration` (Config/PluginConfiguration.cs) -- Configuration data model
- `Response` / `AuthRequest` (Saml.cs) -- SAML request/response handling
- `WebResponse` (WebResponse.cs) -- Generates HTML pages returned to the browser during auth flows
- `RequestHelpers` (Api/RequestHelpers.cs) -- Authorization helper for user-scoped operations
- Frontend JS: `config.js`, `linking.js`, `apiClient.js` -- Admin config UI and user linking UI

**Dependencies:**
- Duende.IdentityModel.OidcClient 6.0.1 (OIDC client library)
- Newtonsoft.Json 13.0.3 (JSON parsing for role claims)
- System.Security.Cryptography.Xml 6.0.1 (XML signature verification for SAML)
- Jellyfin.Controller / Jellyfin.Model 10.11.0
- Target framework: net9.0

---

## 2. HTTP Endpoint Inventory

### 2.1 Unauthenticated Endpoints (No Auth Required)

| Method | Route | Handler | Purpose |
|--------|-------|---------|---------|
| GET | `/sso/OID/r/{provider}`, `/sso/OID/redirect/{provider}` | `OidPost` | OIDC callback from IdP |
| GET | `/sso/OID/p/{provider}`, `/sso/OID/start/{provider}` | `OidChallenge` | Initiate OIDC login |
| POST | `/sso/OID/Auth/{provider}` | `OidAuth` | Complete OIDC auth, issue Jellyfin session |
| GET | `/sso/OID/GetNames` | `OidProviderNames` | List OIDC provider names |
| POST | `/sso/SAML/p/{provider}`, `/sso/SAML/post/{provider}` | `SamlPost` | SAML callback from IdP |
| GET | `/sso/SAML/p/{provider}`, `/sso/SAML/start/{provider}` | `SamlChallenge` | Initiate SAML login |
| POST | `/sso/SAML/Auth/{provider}` | `SamlAuth` | Complete SAML auth, issue Jellyfin session |
| GET | `/sso/SAML/GetNames` | `SamlProviderNames` | List SAML provider names |
| GET | `/SSOViews/{viewName}` | `GetView` | Serve embedded static assets |

### 2.2 Authenticated Endpoints (Requires User Auth)

| Method | Route | Handler | Auth Level |
|--------|-------|---------|------------|
| POST | `/sso/{mode}/Link/{provider}/{jellyfinUserId}` | `AddCanonicalLink` | Self or Admin |
| DELETE | `/sso/{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}` | `DeleteCanonicalLink` | Self or Admin |
| GET | `/sso/saml/links/{jellyfinUserId}` | `GetSamlLinksByUser` | Self or Admin |
| GET | `/sso/oid/links/{jellyfinUserId}` | `GetOidLinksByUser` | Self or Admin |

### 2.3 Admin-Only Endpoints (Requires `Policies.RequiresElevation`)

| Method | Route | Handler | Purpose |
|--------|-------|---------|---------|
| POST | `/sso/OID/Add/{provider}` | `OidAdd` | Add/overwrite OIDC provider config |
| GET | `/sso/OID/Del/{provider}` | `OidDel` | Delete OIDC provider |
| GET | `/sso/OID/Get` | `OidProviders` | List all OIDC configs (with secrets) |
| GET | `/sso/OID/States` | `OidStates` | Debug: dump all in-flight OIDC states |
| POST | `/sso/SAML/Add/{provider}` | `SamlAdd` | Add/overwrite SAML provider config |
| GET | `/sso/SAML/Del/{provider}` | `SamlDel` | Delete SAML provider |
| GET | `/sso/SAML/Get` | `SamlProviders` | List all SAML configs |
| POST | `/sso/Unregister/{username}` | `Unregister` | Change a user's auth provider |

---

## 3. User Input Entry Points (Per-Endpoint Detail)

### 3.1 `OidChallenge` -- Initiate OIDC Flow

**File:** SSOController.cs:362-428

**Inputs:**
- `provider` (route param) -- Used as dictionary key into `OidConfigs`
- `isLinking` (query param, bool) -- Flags whether this is an account-linking flow
- `Request.Path.Value` -- Checked for `/start/` substring to determine new vs legacy path

**Data Flow:**
1. `provider` looks up `OidConfig` from plugin configuration
2. OIDC client options assembled from config values (endpoint, client ID, secret)
3. `OidcClient.PrepareLoginAsync()` generates a state object
4. State stored in static `StateManager` dictionary keyed by state string
5. User redirected to IdP's authorization URL

**Trust Boundary:** Provider name is attacker-controlled (URL path). A `KeyNotFoundException` is caught and throws `ArgumentException` (unhandled -- returns 500).

---

### 3.2 `OidPost` -- OIDC Callback

**File:** SSOController.cs:97-352

**Inputs:**
- `provider` (route param) -- Dictionary key
- `state` (query param) -- Used to look up `StateManager` via `TryGetValue` (line 118)
- `Request.QueryString.Value` -- Entire query string passed to `oidcClient.ProcessResponseAsync()` (line 151)
- `Request.Path.Value` -- Checked for `/start/` substring

**Data Flow:**
1. Provider config loaded from `OidConfigs[provider]`
2. State validated with `TryGetValue` (line 118) -- returns 400 on missing/expired state (FIXED from v4.0.0.3)
3. Null/empty check on state parameter (line 113)
4. Full query string passed to OIDC library for token exchange (line 151)
5. Claims from the ID token parsed for:
   - Username (from `preferred_username` or configurable claim, or fallback to `sub`)
   - Roles (from configurable `RoleClaim`, potentially nested JSON)
   - Avatar URL (claims interpolated into `AvatarUrlFormat`)
6. State object updated with user info, admin status, folder access, validity
7. If valid, `WebResponse.Generator()` produces an HTML page with `data=state`, `provider`, `baseUrl` interpolated into JavaScript (line 336)
8. If invalid, error returned

**Note:** Role claim JSON parsing at line 209 uses `JsonConvert.DeserializeObject` on claim values. If the claim value is attacker-influenced (compromised IdP or claim injection), arbitrary JSON deserialization occurs via Newtonsoft.Json.

---

### 3.3 `OidAuth` -- Complete OIDC Authentication

**File:** SSOController.cs:508-547

**Inputs:**
- `provider` (route param) -- Dictionary key
- `response` (JSON body as `AuthResponse`):
  - `DeviceID` (string) -- Client-supplied device identifier
  - `DeviceName` (string) -- Client-supplied device name
  - `AppName` (string) -- Client-supplied app name
  - `AppVersion` (string) -- Client-supplied app version
  - `Data` (string) -- The OIDC state value

**Data Flow:**
1. Iterates ALL entries in `StateManager` (line 522) to find one where `State.State == response.Data && Valid`
2. Calls `CreateCanonicalLinkAndUserIfNotExist("oid", provider, username)` -- may create a new Jellyfin user (line 526)
3. Calls `Authenticate()` which:
   - Sets admin/folder/LiveTV permissions on the user (lines 1190-1196)
   - Fetches and saves avatar from external URL (lines 1198-1246)
   - Sets auth provider (lines 1261-1266)
   - Creates a Jellyfin session via `AuthenticateDirect()` (line 1268)
4. Returns `AuthenticationResult` containing session token

**Concern:** `AuthResponse` fields (`DeviceID`, `DeviceName`, `AppName`, `AppVersion`) are entirely client-controlled and passed directly into `AuthenticationRequest` (lines 1253-1259). These are stored in Jellyfin's session tracking. No validation or sanitization.

**Concern:** No authentication required. Anyone who can guess or intercept the OIDC state value can complete authentication.

---

### 3.4 `SamlChallenge` -- Initiate SAML Flow

**File:** SSOController.cs:637-673

**Inputs:**
- `provider` (route param) -- Dictionary key
- `isLinking` (query param, bool)
- `Request.Path.Value` -- Checked for `/start/`

**Data Flow:**
1. Config loaded from `SamlConfigs[provider]`
2. `AuthRequest` created with `SamlClientId` and redirect URI
3. Redirect URL constructed: `config.SamlEndpoint + "?SAMLRequest=" + base64(deflate(xml))` (Saml.cs:399-411)
4. If `isLinking`, `relayState=linking` appended
5. User redirected to SAML IdP

---

### 3.5 `SamlPost` -- SAML Callback

**File:** SSOController.cs:560-627

**Inputs:**
- `provider` (route param) -- Dictionary key
- `relayState` (query param) -- Checked for exact string `"linking"`
- `Request.Form["SAMLResponse"]` (form POST body) -- Base64-encoded SAML XML assertion from IdP

**Data Flow:**
1. `new Response(config.SamlCertificate, Request.Form["SAMLResponse"])` -- Creates SAML response object (line 579)
2. `Response` constructor calls `LoadXmlFromBase64()` which Base64-decodes and parses XML (Saml.cs:47-48, 92-93)
3. **`IsValid()` is called** (line 581) -- signature verified, reference scope checked, expiration checked (FIXED in v4.0.0.4)
4. Role attributes extracted via `GetCustomAttributes("Role")` (line 595)
5. If roles are valid (or no roles configured), `WebResponse.Generator()` produces HTML with the **raw SAML XML re-encoded as Base64** in the `data` parameter (line 610)
6. The generated HTML page will POST this data back to `SamlAuth`

**Remaining architectural concern:** While signature verification is now enforced, the SAML assertion is still round-tripped through the client browser. See SSO-02.

---

### 3.6 `SamlAuth` -- Complete SAML Authentication

**File:** SSOController.cs:726-831

**Inputs:**
- `provider` (route param) -- Dictionary key
- `response` (JSON body as `AuthResponse`):
  - `Data` (string) -- Base64-encoded SAML XML assertion (client-supplied)
  - `DeviceID`, `DeviceName`, `AppName`, `AppVersion` -- Client device info

**Data Flow:**
1. `new Response(config.SamlCertificate, response.Data)` -- Parses the SAML assertion from the client POST body (line 743)
2. **`IsValid()` is called** (line 745) -- signature verified (FIXED in v4.0.0.4)
3. Roles extracted, admin/folder/LiveTV permissions determined (lines 760-811)
4. Username extracted via `samlResponse.GetNameID()` (line 813)
5. `CreateCanonicalLinkAndUserIfNotExist()` -- may create user
6. `Authenticate()` -- issues Jellyfin session

**Note:** The SAML response data comes from the client (not directly from the IdP), but signature verification in `IsValid()` now ensures the assertion originated from the expected IdP and has not been tampered with.

---

### 3.7 `AddCanonicalLink` -- Link SSO Identity to Jellyfin Account

**File:** SSOController.cs:956-972

**Inputs:**
- `mode` (route: "saml" or "oid")
- `provider` (route)
- `jellyfinUserId` (route, GUID)
- `authResponse` (JSON body as `AuthResponse`)

**Data Flow:**
1. `RequestHelpers.AssertCanUpdateUser()` checks that the authenticated user is either the target user or an admin (line 958)
2. Delegates to `SamlLink()` or `OidLink()` based on mode
3. `SamlLink()` creates a `Response` from `authResponse.Data` and calls `IsValid()` (lines 1087-1091, FIXED in v4.0.0.4)
4. `OidLink()` matches `authResponse.Data` against StateManager entries (line 1123)

---

### 3.8 `DeleteCanonicalLink` -- Unlink SSO Identity

**File:** SSOController.cs:982-1005

**Inputs:**
- `mode`, `provider`, `jellyfinUserId`, `canonicalName` (all route params)

**Data Flow:**
1. Authorization check via `AssertCanUpdateUser()`
2. Verifies that `canonicalName` is actually linked to `jellyfinUserId` (lines 993-998)
3. Removes the link from config

---

### 3.9 `Unregister` -- Change User Auth Provider

**File:** SSOController.cs:841-847

**Inputs:**
- `username` (route param)
- `provider` (string from request body)

**Data Flow:**
1. Admin-only (`Policies.RequiresElevation`)
2. Looks up user by name, sets `AuthenticationProviderId` to the supplied provider string
3. **User changes are never persisted** -- `_userManager.UpdateUserAsync(user)` is never called

---

### 3.10 `GetView` -- Serve Static Assets

**File:** SSOViewsController.cs:81-85

**Inputs:**
- `viewName` (route param) -- Matched against embedded resource names

**Data Flow:**
1. Looks up `viewName` in the list from `SSOPlugin.Instance.GetViews()` (line 58)
2. Uses exact string match against `PluginPageInfo.Name`
3. Returns the embedded resource stream with appropriate MIME type

**Bounded:** The view name must exactly match a predefined set of names. No path traversal possible since it's matching against a whitelist, not constructing file paths.

---

### 3.11 `WebResponse.Generator` -- HTML Response Generation

**File:** WebResponse.cs:416-516

**Inputs (all from server-side):**
- `data` -- OIDC state string or Base64-encoded SAML XML
- `provider` -- Provider name (originally from URL route)
- `baseUrl` -- Computed from request headers + config overrides
- `mode` -- "OID" or "SAML"
- `isLinking` -- Boolean

**Data Flow:**
1. `baseUrl` converted to Punycode via `IdnMapping.GetAscii()` (line 423)
2. All parameters string-interpolated directly into JavaScript source code (lines 439, 464, 466, 480, 482, 506)
3. The generated HTML page:
   - Embeds Jellyfin web UI in a sandboxed iframe
   - Waits for `localStorage` to be populated with device credentials
   - POSTs device info + `data` to `/sso/{mode}/Auth/{provider}`
   - Stores the returned session token in `localStorage`
   - Redirects to Jellyfin web UI

---

## 4. Data Flow Diagrams

### 4.1 OIDC Authentication Flow

```
User Browser           Jellyfin+SSO Plugin          OIDC Identity Provider
     |                       |                              |
     |-- GET /sso/OID/start/{provider} ------------------>  |
     |                       |                              |
     |                       |-- PrepareLoginAsync() -----> |
     |                       |<-- AuthorizeState ---------- |
     |                       |                              |
     |                       |-- Store state in             |
     |                       |   static StateManager        |
     |                       |                              |
     |<-- 302 Redirect to IdP auth URL ------------------- |
     |                       |                              |
     |-- (User authenticates at IdP) --------------------> |
     |                       |                              |
     |<-- 302 Redirect to /sso/OID/r/{provider}?state=...&code=...
     |                       |                              |
     |-- GET /sso/OID/r/{provider}?state=...&code=... --> |
     |                       |                              |
     |                       |-- TryGetValue(state)         |
     |                       |   (returns 400 if invalid)   |
     |                       |-- ProcessResponseAsync() --> |
     |                       |   (exchanges code for token) |
     |                       |<-- ID Token + Claims ------- |
     |                       |                              |
     |                       |-- Parse claims:              |
     |                       |   username, roles, avatar    |
     |                       |-- Update StateManager        |
     |                       |                              |
     |<-- HTML page with JS (WebResponse.Generator) ------ |
     |                       |                              |
     |-- (JS extracts device info from localStorage) ----- |
     |                       |                              |
     |-- POST /sso/OID/Auth/{provider}                     |
     |   {DeviceID, DeviceName, AppName, AppVersion, Data} |
     |                       |                              |
     |                       |-- Lookup state by Data       |
     |                       |-- CreateUser if not exists   |
     |                       |-- Set permissions            |
     |                       |-- Fetch avatar (SSRF risk)   |
     |                       |-- AuthenticateDirect()       |
     |                       |                              |
     |<-- {AccessToken, User} (Jellyfin session) --------- |
     |                       |                              |
     |-- (JS stores token in localStorage, redirects) ---- |
```

### 4.2 SAML Authentication Flow

```
User Browser           Jellyfin+SSO Plugin          SAML Identity Provider
     |                       |                              |
     |-- GET /sso/SAML/start/{provider} ----------------> |
     |                       |                              |
     |<-- 302 Redirect to IdP with SAMLRequest ----------- |
     |                       |                              |
     |-- (User authenticates at IdP) --------------------> |
     |                       |                              |
     |<-- POST /sso/SAML/post/{provider}                   |
     |   Form: SAMLResponse=<Base64 XML>                   |
     |                       |                              |
     |                       |-- new Response(cert, saml)   |
     |                       |-- IsValid() CALLED           |
     |                       |   (signature verified)       |
     |                       |-- Extract roles              |
     |                       |                              |
     |<-- HTML page with JS (data = base64(saml XML)) ---- |
     |                       |                              |
     |   [Client has full control over data in transit]     |
     |                       |                              |
     |-- POST /sso/SAML/Auth/{provider}                    |
     |   {DeviceID, DeviceName, ..., Data=<base64 XML>}    |
     |                       |                              |
     |                       |-- new Response(cert, Data)   |
     |                       |-- IsValid() CALLED           |
     |                       |   (signature re-verified)    |
     |                       |-- Extract NameID, roles      |
     |                       |-- CreateUser if not exists   |
     |                       |-- Set permissions            |
     |                       |-- AuthenticateDirect()       |
     |                       |                              |
     |<-- {AccessToken, User} (Jellyfin session) --------- |
```

---

## 5. Authentication & Authorization Architecture

### 5.1 Endpoint Protection Model

The plugin uses three tiers of access control:

1. **Unauthenticated** -- All SSO flow endpoints (`OidChallenge`, `OidPost`, `OidAuth`, `SamlChallenge`, `SamlPost`, `SamlAuth`, `GetNames`, `GetView`). These must be unauthenticated by design since they're part of the login flow itself.

2. **Authenticated (Self or Admin)** -- Link management endpoints use `[Authorize]` + `RequestHelpers.AssertCanUpdateUser()` which checks:
   - Is the authenticated user the same as `jellyfinUserId`? OR
   - Does the authenticated user have `PermissionKind.IsAdministrator`?
   - Additionally checks `EnableUserPreferenceAccess` when `restrictUserPreferences=true`

3. **Admin-Only** -- Config management endpoints use `[Authorize(Policy = Policies.RequiresElevation)]` which requires Jellyfin administrator privileges.

### 5.2 State Management

OIDC state is managed via a **static in-memory dictionary** (`StateManager`):
- Keyed by the OIDC state parameter string
- Values are `TimedAuthorizeState` objects containing: OIDC library state, creation time, validity flag, username, admin flag, folders, linking flag, LiveTV flags, avatar URL
- Invalidation: States older than 1 minute are removed, but **only when `Invalidate()` is called** -- which only happens at the start of `OidChallenge()` (line 364)
- No periodic cleanup; states accumulate between challenge requests
- State lookup in `OidPost` now uses `TryGetValue` (line 118) for safe access (FIXED in v4.0.0.4)

SAML has **no server-side state**. The entire SAML assertion is round-tripped through the client browser (encoded in the HTML page, then POSTed back). Signature verification is now enforced on both legs of the round-trip (FIXED in v4.0.0.4).

### 5.3 User Creation

When a user authenticates via SSO for the first time:
1. Plugin looks up canonical link (SSO identity -> Jellyfin user ID)
2. If no link exists, looks up Jellyfin user by the SSO username
3. If no user exists, **auto-creates a Jellyfin user** with:
   - Username from the SSO claim
   - Auth provider set to the SSO plugin
   - Random 64-byte password (Base64 encoded, cryptographically generated)
4. Creates a canonical link mapping the SSO identity to the Jellyfin user ID

### 5.4 Permission Model

When `EnableAuthorization` is true in the provider config, on **every login** the plugin overwrites:
- `IsAdministrator` permission (based on role matching)
- `EnableAllFolders` permission
- Folder access list (based on role-folder mappings or defaults)
- `EnableLiveTvAccess` and `EnableLiveTvManagement`

This means IdP role changes take effect on next login, but also means a compromised SSO flow can escalate privileges.

---

## 6. Trust Boundaries

```
+------------------------------------------------------------------+
|  EXTERNAL (Untrusted)                                            |
|                                                                  |
|  [User Browser] ----HTTP----> [Jellyfin + SSO Plugin]            |
|       |                              |                           |
|       | All route params,            | Config values used        |
|       | query params, form data,     | to build OIDC/SAML        |
|       | JSON bodies                  | requests and URLs         |
|       |                              |                           |
|  [OIDC/SAML IdP] ---callback--> [SSO Plugin]                    |
|       |                              |                           |
|       | ID tokens, SAML assertions,  | Claims used for:          |
|       | claims, attributes           | - username                |
|       |                              | - role/permission mapping |
|       |                              | - avatar URL (SSRF)       |
|       |                              | - admin escalation        |
+------------------------------------------------------------------+
|  INTERNAL (Trusted)                                              |
|                                                                  |
|  [Jellyfin UserManager] -- creates/updates users                 |
|  [Jellyfin SessionManager] -- issues session tokens              |
|  [Jellyfin ProviderManager] -- saves avatar images               |
|  [Plugin Configuration XML] -- stores provider configs + secrets |
|  [Static StateManager Dictionary] -- in-memory OIDC state        |
+------------------------------------------------------------------+
```

**Key trust boundary violations (remaining):**
- Client browser is trusted to relay SAML assertions faithfully (mitigated: signature now re-verified on receipt)
- IdP claims are trusted for privilege assignment without independent validation
- `AuthResponse` fields from the client are trusted without sanitization

---

## 7. Security Findings

### FIXED

#### 7.1 SAML Signature Now Verified (was: SAML Signature Never Verified)

**Location:** SSOController.cs:581, 745, 1089; Saml.cs:99-112
**Status:** FIXED in v4.0.0.4

The `Response.IsValid()` method is now called in all three SAML code paths before any claims are extracted:
- `SamlPost` (line 581): Validates assertion from IdP callback
- `SamlAuth` (line 745): Validates assertion from client POST
- `SamlLink` (line 1089): Validates assertion for account linking

Forged SAML assertions without a valid signature are now rejected.

#### 7.2 SAML Assertion Round-Trip Mitigated (was: SAML Assertion Tampering via Client Round-Trip)

**Location:** SSOController.cs:610 (SamlPost), SSOController.cs:743 (SamlAuth)
**Status:** Mitigated in v4.0.0.4 (downgraded from Critical to Low)

The SAML assertion is still round-tripped through the client browser. However, since `IsValid()` is now called in both `SamlPost` and `SamlAuth`, any modification to the assertion in transit will fail signature verification. The architectural concern remains but exploitation now requires a valid IdP-signed assertion.

#### 7.3 State Lookup Exception Handled (was: State Parameter Lookup Without Bounds Check)

**Location:** SSOController.cs:113-121
**Status:** FIXED in v4.0.0.4

The state parameter is now checked for null/empty (line 113) and looked up via `TryGetValue` (line 118), returning a clean 400 error instead of an unhandled exception with stack trace.

### HIGH (Open)

#### 7.4 JavaScript Injection via String Interpolation in WebResponse

**Location:** WebResponse.cs:426-514
**Status:** Open

The `Generator()` method interpolates `data`, `provider`, `baseUrl`, `mode`, and `isLinking` directly into JavaScript source code using C# string interpolation/concatenation:

```csharp
var data = '" + data + @"';
// ...
var url = '" + punycodeBaseUrl + "/sso/" + mode + "/Auth/" + provider + @"';
// ...
'" + $"{punycodeBaseUrl}/sso/{mode}/Link/{provider}/" + @"' + jfUser;
```

The `provider` parameter originates from a URL route segment controlled by the attacker. If a provider name contains `'` or `\`, it can break out of the JavaScript string context.

**Impact:** Cross-Site Scripting (XSS). An attacker who creates a provider with a specially crafted name (requires admin) can inject arbitrary JavaScript in the context of the Jellyfin domain.

**Note:** `baseUrl` passes through `IdnMapping.GetAscii()` which would reject many special characters, providing partial mitigation for that specific parameter.

#### 7.5 SSRF via Avatar URL

**Location:** SSOController.cs:1198-1246
**Status:** Open (partially improved: now uses `IHttpClientFactory`)

When `AvatarUrlFormat` is configured, the server constructs a URL from OIDC claim values and makes an HTTP GET request to it:

```csharp
using var client = _httpClientFactory.CreateClient();  // Line 1202 - improved from new HttpClient()
var avatarResponse = await client.GetAsync(avatarUrl);  // Line 1209
```

The URL is constructed by replacing `@{claim_type}` placeholders with claim values (lines 172-174). If an attacker controls claim values, they can direct the server to make requests to internal network services, cloud metadata endpoints, or arbitrary external hosts.

Additional concerns:
- Content-type validation only checks `startsWith("image")` (line 1217)
- No response size limit
- No explicit timeout configuration
- Follows redirects by default

#### 7.6 XSS via innerHTML in Frontend JavaScript

**Location:** linking.js:38-51, 108-128; config.js:60-78
**Status:** Open

Multiple locations use `innerHTML` with unsanitized data:

**linking.js:41** -- Provider name from API:
```javascript
provider_config.innerHTML = `<label...>${provider_name}</label>...`;
```

**linking.js:112-123** -- Canonical name (SSO identity) from API:
```javascript
out.innerHTML = `<input ... data-id="${canonical_name}" ... />
  <span class="checkbox-label">${canonical_name}</span>`;
```

**config.js:63-69** -- Folder name from Jellyfin API:
```javascript
out.innerHTML = `<input ... /><span>${folder.Name}</span>`;
```

**Impact:** If an attacker can control provider names, SSO identity names, or folder names, they can inject arbitrary HTML/JavaScript in the admin configuration or user linking pages.

#### 7.7 Deletion via HTTP GET (CSRF)

**Location:** SSOController.cs:448-455 (`OidDel`), SSOController.cs:696-704 (`SamlDel`)
**Status:** Open

Provider deletion uses HTTP GET:
```csharp
[HttpGet("OID/Del/{provider}")]
public void OidDel(string provider)
```

**Impact:** An admin who visits a page with `<img src="https://jellyfin-host/sso/OID/Del/myProvider">` will inadvertently delete that SSO provider. GET requests are not protected against CSRF by standard browser security mechanisms.

### MEDIUM (Open)

#### 7.8 Thread Safety -- Static Dictionary Without Concurrent Access Protection

**Location:** SSOController.cs:51
**Status:** Open

```csharp
private static readonly IDictionary<string, TimedAuthorizeState> StateManager = new Dictionary<string, TimedAuthorizeState>();
```

`StateManager` is a plain `Dictionary` shared across all requests via a `static` field. Concurrent operations (Add, Remove, iteration in `Invalidate()` and `OidAuth`) can cause:
- `InvalidOperationException` from concurrent modification during enumeration
- Lost updates / race conditions
- Potential for state confusion between users

**`Invalidate()`** (lines 1271-1281) modifies the dictionary while iterating it:
```csharp
foreach (var kvp in StateManager) {
    // ...
    StateManager.Remove(kvp.Key); // Modification during enumeration
}
```

#### 7.9 Information Disclosure -- Sensitive Config Data in API Responses

**Location:** SSOController.cs:463-466 (`OidProviders`), SSOController.cs:493-497 (`OidStates`)
**Status:** Open

- `OidProviders` returns full `OidConfig` objects including `OidSecret` (client secret)
- `SamlProviders` (line 712) returns full `SamlConfig` including `SamlCertificate`
- `OidStates` returns the full `StateManager` contents including OIDC `AuthorizeState` objects (which may contain tokens)

While these are admin-only endpoints, they expose secrets that should be redacted even in admin views.

#### 7.10 Unregister Endpoint Doesn't Persist Changes

**Location:** SSOController.cs:841-847
**Status:** Open

```csharp
public ActionResult Unregister(string username, [FromBody] string provider)
{
    User user = _userManager.GetUserByName(username);
    user.AuthenticationProviderId = provider;
    return Ok();
}
```

`_userManager.UpdateUserAsync(user)` is never called, so the provider change is never saved. This is a functional bug, but also a security concern: an admin may believe they've unregistered a user from SSO when the change was silently lost.

#### 7.11 No SAML Audience or Recipient Validation

**Location:** Saml.cs:99-112
**Status:** Open

Even with signature verification now enforced, the SAML `Response` class does not validate Audience Restriction, Recipient, InResponseTo, or NotBefore conditions. A valid SAML assertion from the same IdP, intended for a different service provider, could be replayed against Jellyfin.

#### 7.12 XPath Injection in SAML Attribute Queries

**Location:** Saml.cs:265, 276
**Status:** Open (Informational)

```csharp
public string GetCustomAttribute(string attr) {
    var node = _xmlDoc.SelectSingleNode(
        "/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='" + attr + "']/saml:AttributeValue",
        _xmlNameSpaceManager);
    return node?.InnerText;
}
```

The `attr` parameter is concatenated directly into an XPath expression. In the current code, `attr` values are hardcoded strings ("Role"), so this is not directly exploitable. However, these are `public` methods, and any future use with user-controlled input would create an XPath injection vulnerability.

### LOW (Open)

#### 7.13 Newtonsoft.Json Deserialization of Claim Values

**Location:** SSOController.cs:209

```csharp
var json = JsonConvert.DeserializeObject<IDictionary<string, object>>(claim.Value);
```

Claim values from the IdP are deserialized using Newtonsoft.Json. While deserializing to `IDictionary<string, object>` (not `object` or with `TypeNameHandling`) limits the attack surface, this is still processing untrusted input.

#### 7.14 No Rate Limiting on Authentication Endpoints

**Status:** Open

None of the authentication endpoints implement rate limiting. An attacker could:
- Brute-force OIDC state values by rapidly calling `OidAuth`
- Cause resource exhaustion by triggering many OIDC flows (each creates a state entry)
- Flood `SamlAuth` with assertion submissions (each requires XML parsing and signature verification)

#### 7.15 Avatar File Extension from Content-Type

**Location:** SSOController.cs:1222

```csharp
var extension = contentType.Split("/").Last();
```

The file extension for saved avatar images is derived from the Content-Type header's subtype. A malicious server could return `Content-Type: image/svg+xml` which would pass the `startsWith("image")` check and result in an SVG file (potential stored XSS).

#### 7.16 Provider Name Enumeration

**Location:** SSOController.cs:472-476 (`OidProviderNames`), SSOController.cs:482-486 (`SamlProviderNames`)
**Status:** Open

These unauthenticated endpoints return all configured provider names, allowing reconnaissance of the SSO configuration.

#### 7.17 Log Injection via relayState

**Location:** SSOController.cs:574-575
**Status:** Open

```csharp
_logger.LogInformation($"SAML request has relayState of {relayState}");
```

Uses C# string interpolation instead of structured logging, allowing log injection via newline characters.

#### 7.18 OIDC Error Details Reflected to Client

**Location:** SSOController.cs:155, 417
**Status:** Open

Error details from the OIDC library (`result.Error`, `result.ErrorDescription`) are returned directly to the client, potentially exposing internal endpoint URLs or configuration details.

### PARTIALLY FIXED

#### 7.19 HttpClient Best Practices

**Location:** SSOController.cs:1202
**Status:** Partially Fixed in v4.0.0.4

The `HttpClient` is now created via `IHttpClientFactory` (line 1202), resolving socket exhaustion. However, the client still lacks explicit timeout configuration, response size limits, and redirect control.

---

## 8. Configuration Security

### 8.1 Sensitive Data in Plugin Configuration

The plugin stores all configuration in Jellyfin's XML-serialized plugin configuration, including:
- OIDC client secrets (`OidSecret`)
- SAML certificates (`SamlCertificate`)
- All canonical link mappings (SSO identity <-> Jellyfin user ID)

This configuration is accessible via the admin API and stored in the Jellyfin data directory.

### 8.2 Security-Weakening Configuration Options

Several config flags explicitly weaken security:
- `DisableHttps` -- Allows HTTP for OIDC discovery (disables TLS requirement)
- `DisablePushedAuthorization` -- Disables PAR (less secure authorization flow)
- `DoNotValidateEndpoints` -- Skips OIDC endpoint validation
- `DoNotValidateIssuerName` -- Skips OIDC issuer name validation

These are documented as "(Insecure)" in the UI but provide no additional guardrails.

---

## 9. Attack Surface Summary

| Attack Vector | Severity | Auth Required | Entry Point | Status |
|---------------|----------|---------------|-------------|--------|
| Forged SAML assertion -> admin access | ~~CRITICAL~~ | No | `POST /sso/SAML/Auth/{provider}` | **FIXED** |
| SAML assertion tampering (client round-trip) | ~~CRITICAL~~ Low | No | `POST /sso/SAML/Auth/{provider}` | **Mitigated** |
| XSS via WebResponse JS interpolation | HIGH | No (but needs crafted provider name) | `GET /sso/OID/r/{provider}`, `POST /sso/SAML/post/{provider}` | Open |
| SSRF via avatar URL | HIGH | No (triggered by OIDC claims) | `POST /sso/OID/Auth/{provider}` | Open |
| Stored XSS via innerHTML | HIGH | No (IdP-controlled values) | Admin config page, Linking page | Open |
| CSRF provider deletion | HIGH | Admin session | `GET /sso/OID/Del/{provider}` | Open |
| Race condition in StateManager | MEDIUM | No | All OIDC endpoints | Open |
| Secret disclosure in admin API | MEDIUM | Admin | `GET /sso/OID/Get` | Open |
| Unhandled exception on invalid state | ~~MEDIUM~~ | No | `GET /sso/OID/r/{provider}` | **FIXED** |
| No SAML Audience/Recipient validation | MEDIUM | No | `POST /sso/SAML/Auth/{provider}` | Open |
| Unregister doesn't persist | MEDIUM | Admin | `POST /sso/Unregister/{username}` | Open |
| Provider name enumeration | LOW | No | `GET /sso/OID/GetNames` | Open |
| Log injection via relayState | LOW | No | `POST /sso/SAML/post/{provider}` | Open |
| OIDC error details reflected | LOW | No | `GET /sso/OID/r/{provider}` | Open |
