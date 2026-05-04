# Coolify — Security Audit (Branch: `claude/coolify-security-audit-2hpkk`)

**Scope:** full codebase review focused on the team's stated worry — that an
authenticated attacker (or, where relevant, an unauthenticated one) could
obtain SSH access to managed servers, which Coolify connects to as **root**.
The audit covered SSH/RCE surfaces, AuthN/AuthZ, multi-tenancy, secrets at rest,
API surface, webhooks, OAuth, sessions, CORS, and logging.

**Headline:** the SSH command-shipping pipeline itself is largely sound (heredoc
+ `escapeshellarg` for connection params, encrypted private keys at rest,
0600 enforcement, strong Git URL/ref allowlists). **The break-glass risk is in
authorization, not in shell quoting.** `ApplicationPolicy` and most of
`ServerPolicy` have been intentionally short-circuited to `return true` — every
"check" is commented out. Combined with mass-assignable `team_id` on key models
and a magic-link token with no expiry, a logged-in **MEMBER of any team** can
take over applications and servers belonging to **any other team on the same
instance**, and from there reach root SSH on the managed servers.

Severities: **P0 = exploit chain to root SSH on managed servers / cross-tenant
takeover**, **P1 = serious data exposure or auth bypass**, **P2 = hardening**.

---

## P0 — Critical (fix before next release)

### P0-1. `ApplicationPolicy` is fully disabled — every method returns `true`
**File:** `app/Policies/ApplicationPolicy.php` (entire file)

Every policy method has the real check commented out and an unconditional
`return true;` underneath, with the comment `// Authorization temporarily
disabled`. This includes `view`, `viewAny`, `create`, `update`, `delete`,
`forceDelete`, `restore`, `deploy`, `manageDeployments`, `manageEnvironment`,
`cleanupDeploymentQueue`.

```php
public function deploy(User $user, Application $application): bool
{
    // Authorization temporarily disabled
    /*
    return $user->teams->contains('id', $application->team()->first()->id);
    */
    return true;
}
```

**Impact:** every Livewire/API caller that runs `$this->authorize('deploy',
$application)` is a no-op. A user authenticated as MEMBER of team A can
**deploy, redeploy, edit env vars, force-delete, and rotate** applications
owned by any other team B on the instance. Because deployments execute
arbitrary build steps as root on team B's server (Nixpacks / Dockerfile /
custom build commands), this is a direct path to **root RCE on every server
managed by the instance**, from any logged-in account.

**Fix:** restore the original checks. The pattern in the comments is correct
(team membership + role for write actions). Add a Pest feature test per policy
method asserting that a MEMBER of team B is denied.

---

### P0-2. `ServerPolicy` write/management methods are disabled
**File:** `app/Policies/ServerPolicy.php:29-103`

`view()` is correctly scoped (`$user->teams->contains('id', $server->team_id)`),
but `create`, `update`, `delete`, `manageProxy`, `manageSentinel`,
`manageCaCertificate`, `viewSecurity` all return `true` with the real check
commented out:

```php
public function delete(User $user, Server $server): bool
{
    // return $user->isAdmin() && $user->teams->contains('id', $server->team_id);
    return true;
}
```

**Impact (assuming the team-scope leak in P0-1 is closed):** even within a
single team, a MEMBER can delete servers, reconfigure the proxy, manage
Sentinel, and view security pages. Worse — `view()` is the *only* gate, and
nothing prevents a member from one team from **calling** the action endpoints
with a UUID of a server in another team if the controller/Livewire handler
forgets to authorize (and most of them rely on the policy). Several Livewire
components use `Server::ownedByCurrentTeam()` which protects them, but every
component that does `Server::whereUuid(...)` does **not**.

**Fix:** uncomment the real checks. Require `isAdmin()` for proxy/sentinel/CA
management and `isOwner()` for delete. Add tests.

---

### P0-3. OAuth callback logs in any user matched by email without identity confirmation
**File:** `app/Http/Controllers/OauthController.php:18-42`

```php
public function callback(string $provider)
{
    $oauthUser = get_socialite_provider($provider)->user();
    $user = User::whereEmail($oauthUser->email)->first();
    if (! $user) {
        // ... maybe create
    }
    Auth::login($user);
    return redirect('/');
}
```

There is no check that:
- the OAuth provider has actually verified ownership of that email (e.g. GitHub
  has unverified secondary emails; self-hosted GitLab/Authentik/Keycloak may
  accept user-supplied email at signup);
- the existing local Coolify user has previously *linked* this OAuth identity;
- the local user even uses OAuth at all (they could be a password user).

**Impact:** classic *pre-account-takeover via OAuth email match*. If an
instance admin enables any OAuth provider that doesn't enforce verified email
ownership (or any self-hosted IdP), an attacker who controls a fresh OAuth
identity with a victim's email gains immediate session as that victim — which,
combined with P0-1/P0-2, means root SSH on the victim team's servers.

**Fix:**
1. Persist OAuth identity → user mapping in a dedicated `oauth_accounts` table
   keyed by `(provider, provider_user_id)`. Reject email-only matching.
2. For account creation, require a verified email claim from the provider, or
   send a confirmation email before creating.
3. For linking an OAuth identity to an existing password account, require the
   user to be already authenticated and explicitly link.

---

### P0-4. Magic-link token has no expiry, no single-use, no nonce
**File:** `app/Http/Controllers/Controller.php:97-125`, `routes/web.php:100`

```php
public function link()
{
    $token = request()->get('token');
    if ($token) {
        $decrypted = Crypt::decryptString($token);
        $email = str($decrypted)->before('@@@');
        $password = str($decrypted)->after('@@@');
        $user = User::whereEmail($email)->first();
        // ...
        if (Hash::check($password, $user->password)) {
            // ...
            Auth::login($user);
```

The token is `Crypt::encryptString("$email@@@$bcrypt_hash")`. No expiry, no
JTI, no DB-backed single-use record. The link works **forever** until the
user changes their password. `Crypt::encryptString` uses `APP_KEY`, so a single
leak of an APP_KEY-encrypted token (in a referrer header, browser history,
mailbox archive, MTA logs, support-ticket paste, sentry breadcrumb…) is a
**permanent backdoor**.

**Impact:** persistent account takeover from any leaked magic link. Because
this is also the team-invitation-acceptance path, leaked invitation links are
durable as well.

**Fix:** issue tokens with `URL::temporarySignedRoute(...)` and a short TTL, or
back them with a `magic_links` table that records `(token_hash, user_id,
expires_at, consumed_at)`. Always delete on use. Add a 5/min throttle.

---

## P1 — High

### P1-1. Mass-assignable `team_id` on `PrivateKey`, `GithubApp`, `GitlabApp`
**Files:** `app/Models/PrivateKey.php:35-42`, `app/Models/GithubApp.php:9-29`,
`app/Models/GitlabApp.php` (similar)

```php
// PrivateKey
protected $fillable = ['name', 'description', 'private_key',
    'is_git_related', 'team_id', 'fingerprint'];

// GithubApp
protected $fillable = ['team_id', 'private_key_id', 'name', /* ... */
    'client_secret', 'webhook_secret', 'is_system_wide', 'is_public', /* ... */];
```

Any controller / Livewire component / API endpoint that does
`PrivateKey::create($request->all())` (or `->update($request->all())`, or
`->fill(...)`) can be abused to set `team_id` to another team's id (or `0` for
the system/root team), or to flip `is_system_wide=true` on a GitHub App. Given
P0-1, this becomes a key/token reassignment primitive: attacker creates a
PrivateKey scoped to the victim team, then attaches it to any of the victim's
servers via the now-bypassed authorization.

**Fix:** drop `team_id`, `is_system_wide`, `client_secret`, `webhook_secret`
from `$fillable`. Set them explicitly in factories/services from server-side
context (`currentTeam()->id`).

---

### P1-2. Wildcard CORS on `api/*` and `sanctum/csrf-cookie`
**File:** `config/cors.php`

```php
'paths' => ['api/*', 'sanctum/csrf-cookie'],
'allowed_methods' => ['*'],
'allowed_origins' => ['*'],
'allowed_headers' => ['*'],
'supports_credentials' => false,
```

`supports_credentials: false` blocks cookie-auth abuse, but Sanctum **bearer
tokens** are passed in `Authorization` headers — which CORS only protects
against being *added by JS*, not against being read in a response. Any site a
victim visits can JS-`fetch` `https://coolify.example.com/api/v1/servers` and
read the response *if it can supply a token* (e.g. the victim previously
pasted a token into a malicious app, the token was phished, or the attacker
got it via a leaked log line). It also exposes the CSRF-cookie endpoint to
all origins.

**Fix:** restrict `allowed_origins` to the configured Coolify domain(s).
Drop `sanctum/csrf-cookie` from CORS unless first-party SPA actually needs it.

---

### P1-3. GitHub/GitLab app secrets are not encrypted at rest
**Files:** `app/Models/GithubApp.php:33-42`, `app/Models/GitlabApp.php`

```php
protected $casts = ['is_public' => 'boolean', 'is_system_wide' => 'boolean', 'type' => 'string'];
protected $hidden = ['client_secret', 'webhook_secret'];
```

`$hidden` only suppresses default JSON serialization — it does **not** encrypt.
Compare to `PrivateKey` where `'private_key' => 'encrypted'` is set. A DB
read primitive (SQLi, leaked dump, replica access) yields plaintext OAuth
client secrets and webhook signing secrets — enabling webhook spoofing
(which dispatches deployments → root RCE) and OAuth impersonation.

**Fix:** add `'client_secret' => 'encrypted', 'webhook_secret' => 'encrypted'`
casts and write a migration to re-encrypt existing rows (mirror
`2024_09_16_111428_encrypt_existing_private_keys.php`). Same for GitLab's
`app_secret` and `webhook_token`.

---

### P1-4. Registration enabled with no email verification by default
**File:** `config/fortify.php:135-146`

`Features::registration()` is on; `Features::emailVerification()` is commented
out. Combined with **P0-3**, anyone who can self-register with the email
`admin@victim-org.example` and then log in via OAuth using a provider that
doesn't pre-verify email gets the victim admin's account. Even without OAuth,
unverified registrations are a steady supply of pre-positioned accounts.

**Fix:** enable email verification by default. If self-registration is meant
to be off in production, gate it behind `instanceSettings()->is_registration_enabled`
*and* set the default to `false` for non-cloud installs.

---

### P1-5. GitHub manual-webhook signature check is skipped when `isDev()`
**File:** `app/Http/Controllers/Webhook/Github.php:93-102`

```php
$hmac = hash_hmac('sha256', $request->getContent(), $webhook_secret);
if (! hash_equals($x_hub_signature_256, $hmac) && ! isDev()) {
    // reject
}
```

If `APP_ENV=local` (or whatever `isDev()` keys on) is ever set in production —
which happens when admins copy a `.env.example` or follow stale docs — this
endpoint accepts forged webhooks. Forged webhooks trigger deployments, which
build and run attacker-controlled code as root.

**Fix:** drop the `! isDev()` exception. If devs need to bypass locally, they
can set `manual_webhook_secret_github` to a known value and sign the request
properly.

---

### P1-6. Backup download endpoint hand-rolled in a closure with a "root-team bypass"
**File:** `routes/web.php:327-396`

The closure does `ScheduledDatabaseBackupExecution::where('id', ...)
->firstOrFail()` and conditionally checks team membership only when the
backup's team id is non-zero. Root-team users (`team_id=0`) effectively
bypass team scoping. There's no policy involvement and no signed URL.

**Fix:** move to a controller, gate with a policy, drop the team-id-zero
short-circuit, and use `URL::signedRoute` for the download URL itself.

---

### P1-7. Horizon dashboard not restricted to admins
**File:** `config/horizon.php:73`, no `Gate::define('viewHorizon', ...)`
in `app/Providers/HorizonServiceProvider.php`

Horizon is wired up with `['web']` middleware (auth) but no admin gate. Any
authenticated user (including MEMBER) can view queue contents — and **queued
jobs include `DatabaseBackupJob` instances whose public properties contain
extracted DB passwords** (see also P2-3). It also reveals deployment logs
that leak env vars in dev mode (P2-4).

**Fix:** add `Gate::define('viewHorizon', fn ($user) => $user->isAdmin()
&& $user->canAccessSystemResources())` and apply it via Horizon's
`auth` callback.

---

### P1-8. SSH host-key verification disabled (`StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`)
**File:** `app/Helpers/SshMultiplexingHelper.php:~249`

```
-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
```

Coolify never pins or even records the server host key. An attacker who can
MITM the network path between Coolify and a managed server (BGP hijack, ARP
poisoning on a shared LAN, malicious cloud-network operator, compromised
intermediate router) can impersonate the server, capture commands, and inject
their own — a path to lateral takeover of *every* deployment.

**Fix:** on first successful connection, capture the host key fingerprint and
persist it on the `Server` model. On subsequent connections, use
`-o StrictHostKeyChecking=yes` with a known-hosts file written from the
stored fingerprint. Surface a "host key changed" warning in the UI rather
than silently accepting a new key.

---

### P1-9. `HetznerController` does an unscoped `Team::find($teamId)`
The reconnaissance pass flagged this in `app/Http/Controllers/Api/HetznerController.php`
calling `Team::find($teamId)` from a request parameter without verifying the
authenticated user is a member. IDOR allows reading/operating on any team's
Hetzner integration. (Exact line not re-verified by me — please confirm and
patch with `auth()->user()->teams()->findOrFail($teamId)`.)

---

## P2 — Medium / hardening

### P2-1. No rate limiting on password reset, magic link, OAuth callback, webhooks
`RouteServiceProvider` only limits `api` and `5`-per-min generic. `forgot-password`,
`auth/link`, `auth/{provider}/callback`, and `webhooks/*` are all wide open.
Combined with P0-4 (magic-link tokens never expire) this is a brute-force
amplifier.

### P2-2. Sentinel `/v1/sentinel/push` uses `!==` rather than `hash_equals`
**File:** `routes/api.php:244`. The compared token is a high-entropy ciphertext
so practical exploitation is unlikely, but switch to `hash_equals` for
consistency with the GitHub/GitLab handlers.

### P2-3. `DatabaseBackupJob` holds DB passwords in `public ?string` properties
**File:** `app/Jobs/DatabaseBackupJob.php:161-244`. These are visible in
Horizon's serialized job payload (P1-7) and in any failed-job storage. Convert
to `protected` and zero them out before the job is serialized for retry.

### P2-4. Debug-mode logging of decrypted env vars
**File:** `app/Jobs/ApplicationDeploymentJob.php` (lines ~1527, ~1615-1641).
`if (isDev()) { ... addLogEntry("[DEBUG] real_value: {$resolvedValue}"); }`
prints decrypted secrets into the deployment log shown in the UI. If `isDev()`
returns true in production (misconfigured `.env`), every deployment dumps
secrets into the team-readable log. Replace with `***REDACTED***`.

### P2-5. Remote `.env` written without `chmod 600`
**File:** `app/Models/Service.php:1598-1599`
```php
$envs_base64 = base64_encode($envs->implode("\n"));
$commands[] = "echo '$envs_base64' | base64 -d | tee .env > /dev/null";
```
The remote umask determines whether other local users on the managed server
can read it. Append `&& chmod 600 .env`.

### P2-6. `parseCommandsByLineForSudo` interpolates `$path` unquoted
**File:** `bootstrap/helpers/sudo.php:~82`
```php
return "$line && sudo chown -R $server->user:$server->user $path && sudo chmod -R o-rwx $path";
```
Today `$path` is platform-controlled, but the function takes any command
collection. Quote the substitutions (`'%s'` with `escapeshellarg`) to make
the helper safe against future callers.

### P2-7. `getContainerStatus` interpolates `$container_id`
**File:** `bootstrap/helpers/docker.php:152-158`. Currently safe because all
callers validate via `ValidationPatterns::isValidContainerName()`, but the
helper itself accepts any string. Add `escapeshellarg` inside the helper for
defense in depth.

### P2-8. Stored XSS surface: `{!! $error !!}`
**File:** `resources/views/livewire/server/validate-and-install.blade.php:149`.
The string flows from `ValidateAndInstallServerJob`. Audit every code path
that writes into it to ensure no remote shell output reaches the template
unsanitized; or wrap with `Purify::clean(...)` at render time.

### P2-9. `SESSION_SECURE_COOKIE` not enforced
**File:** `config/session.php:199`. Defaults to `null` unless env is set.
Self-hosters who misconfigure HTTPS get cookies sent over HTTP. Default to
`true` and document the override for HTTP-only dev.

### P2-10. CSRF exempts `webhooks/*` (broad but justified)
`app/Http/Middleware/VerifyCsrfToken.php`. This is necessary for third-party
webhooks but means every webhook handler must do its own auth. Audit each
handler to ensure HMAC verification is present (most are; combined with P1-5).

---

## What looked OK and should not be regressed

These were checked and are healthy — call them out in the next code review so
they aren't refactored away:

- **SSH command shipping (`SshMultiplexingHelper::generateSshCommand`):**
  uses `'bash -se' << \DELIMITER` heredoc with a delimiter derived from
  `base64(Hash::make($command))` (unguessable) and strips any colliding
  occurrence from the command first. User/host/port go through
  `escapeshellarg`. Command injection through this layer is not feasible.
- **`PrivateKey::private_key` is encrypted at rest** (`'encrypted'` cast) and
  files written to `/var/www/html/storage/app/ssh/keys/...` are `chmod 0600`
  with active enforcement on read.
- **`EnvironmentVariable.value`, `S3Storage.key/secret`, `SslCertificate.*`,
  `CloudProviderToken.token`, `OauthSetting`** are all encrypted at rest.
- **`ValidGitRepositoryUrl` and `validateGitRef`** are strict allowlist
  validators that block all shell metacharacters and traversal patterns.
- **`UploadController`** uses `getClientOriginalName` only for extension check
  and stores under a hardcoded filename in a per-resource directory — no
  path traversal.
- **`SafeWebhookUrl` rule** for outbound webhooks blocks private/metadata IPs
  (SSRF mitigation present).
- **Channel auth** in `routes/channels.php` correctly checks team membership
  and user identity for `team.{id}` and `user.{id}` private channels.

---

## Recommended fix order

1. **Today:** restore `ApplicationPolicy` and `ServerPolicy` checks (P0-1, P0-2).
   These are one-file diffs, regression-tested by uncommenting the existing
   commented blocks. Add Pest tests asserting MEMBER-cross-team denial.
2. **This week:**
   - P0-3 OAuth identity table + verified-email requirement.
   - P0-4 magic-link token expiry + single-use.
   - P1-1 strip `team_id`/secrets from `$fillable`.
   - P1-3 encrypt GitHub/GitLab app secrets + migration.
   - P1-5 remove `! isDev()` webhook bypass.
3. **Next sprint:**
   - P1-2 lock down CORS origins.
   - P1-4 enable email verification.
   - P1-6 backup-download policy + signed URL.
   - P1-7 Horizon admin gate.
   - P1-8 host-key pinning.
   - P1-9 Hetzner IDOR.
4. **Hardening backlog:** all P2 items.

---

## Suggested test coverage to add

A Pest feature test that creates two teams with separate users and asserts
that for **every authenticated route**, a member of team B receives 403/404
when targeting a team A resource. This catches the entire P0-1/P0-2 class
of regressions and any future copy-paste mistake.

```php
// tests/Feature/CrossTenantAccessTest.php
it('denies cross-tenant application access for every action', function (string $method, string $route) {
    [$teamA, $teamB] = Team::factory()->count(2)->create();
    // ... seed a victim Application in team A
    actingAs($teamB->users->first())
        ->call($method, route($route, ['application_uuid' => $victim->uuid]))
        ->assertForbidden();
})->with([/* every route in the application namespace */]);
```

---

*Audit performed on branch `claude/coolify-security-audit-2hpkk` from main
`v4.x`, commit `922950de`. All findings reference paths/lines in the tree at
that commit.*
