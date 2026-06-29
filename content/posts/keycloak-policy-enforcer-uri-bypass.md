---
title: "A substring match that turns Keycloak's policy enforcer off"
date: 2026-06-29
draft: false
tags: ["vulnerability-research", "keycloak", "authorization", "disclosure", "ai-assisted"]
summary: "CVE-2026-9800 — Keycloak's policy enforcer used a substring match to detect its own access-denied page, so any authenticated user could append that path and skip every authorization check. The first package I ever audited, and a .contains() that lets everyone in."
ShowToc: true
TocOpen: false
---

## TL;DR

Keycloak's `policy-enforcer` decides whether a request "is" the configured access-denied page by doing a **substring** match on the URL. So if your URL contains that string anywhere, the enforcer concludes you're already on the deny page and lets the request through with a `200` — skipping every role, scope and UMA permission check it was supposed to run. Any authenticated user, any role, any scope, appends `/access-denied` to a path and walks straight past authorization.

No special privileges. No token forgery. The default deny-redirect value is guessable — it's often literally `/access-denied`, or it's printed on the login flow.

This was also the **first package I ever audited** — the first thing I pointed Claude Opus at to hunt for critical bugs — and it landed on the first try, which was a stroke of luck.

- **Advisory:** GHSA-f5p5-6xmx-p252
- **CVE:** CVE-2026-9800
- **Severity:** CVSS 3.1 = 8.1 (High) — authenticated authorization bypass (CWE-1025, comparison using wrong factors)
- **Affected:** `keycloak-policy-enforcer` < 26.6.4, and the 26.0.x LTS line < 26.0.10
- **Fix:** released in 26.6.4 / 26.0.10; advisory published 2026-06-26

## Why a policy-enforcer bug matters

The policy enforcer is the thing standing between an authenticated user and your protected endpoints. Keycloak does the heavy lifting — issues tokens, models resources, scopes, roles and UMA permissions — but the enforcer is what actually *applies* that model to an incoming request inside your app. Its whole selling point, stated in the docs, is **deny by default**: *"requests are denied by default even when no policy is associated with a given resource."*

So when the enforcer can be talked into skipping evaluation entirely, you don't have a weak policy — you have **no policy**. Every role check, every scope check, every UMA permission check you carefully configured is just not run. That's the difference between "this user can't see patient records" and "this user can see, and modify, every patient record."

## The bug

It lives in `PolicyEnforcer.java`, in a tiny helper that answers one question: "is this request just the user landing on the access-denied page?" Because if it is, you *have* to let it through — otherwise the deny page itself would be denied, and you'd loop forever.

Here's how it decides:

```java
// PolicyEnforcer.java
private boolean isDefaultAccessDeniedUri(HttpRequest request) {
    String accessDeniedPath = enforcerConfig.getOnDenyRedirectTo();
    return accessDeniedPath != null
        && request.getURI().contains(accessDeniedPath);   // substring, not equality
}
```

`contains`. Not "is this request *for* the deny page" — "does the deny page string appear *anywhere* in this URL." Path segment, query string, doesn't matter.

And this helper isn't a sleepy corner of the code. It's called from four sites in `PolicyEnforcer.java`, and **three of them short-circuit policy evaluation as granted**:

- when no path config matches the request → return granted,
- inside `isAuthorized` → return `true` outright,
- in `getPathConfig` → return `null`, i.e. "nothing protected here, let it through."

So with a typical `"on-deny-redirect-to": "/access-denied"`, any request whose URL contains `/access-denied` is treated as the deny page and granted. The attacker never has to *reach* the deny page. They just have to carry its name.

A request for `/api/patients/P001` is correctly denied. The exact same token against `/api/patients/P001/access-denied` is granted — same resource, same user, one extra path segment that the app routes to the same handler. The shape of the request never changed; the only thing that changed is that the enforcer pattern-matched a magic word.

## Their fix

The whole bug is `contains` standing in for `equals`. The fix is to stop asking "does the deny string appear somewhere in this URL" and start asking "is this request actually *for* the deny page" — an exact comparison of the parsed request path against the configured deny path:

```java
private boolean isDefaultAccessDeniedUri(HttpRequest request) {
    String accessDeniedPath = enforcerConfig.getOnDenyRedirectTo();
    if (accessDeniedPath == null) return false;
    String path = URI.create(request.getURI()).getPath();
    return path.equals(accessDeniedPath);   // exact match on the path component
}
```

Keycloak classified it as CWE-1025 — *comparison using wrong factors* — which is exactly it: the right values were on hand, the comparison just looked at the wrong characteristic of them. The fix shipped in 26.6.4 and was back-ported to the 26.0.x LTS line as 26.0.10.

## The disclosure process

This is the part I want to be honest about, because the clean "found a CVE" headline hides how the sausage gets made.

I didn't report one bug — I reported **three**, in separate threads, because that's what the Keycloak security team asks for. Only one became a CVE. The other two were dismissed as working-as-designed, and the maintainers were right both times:

- **JWSInput doesn't verify signatures.** True, but the policy-enforcer isn't the component that's *supposed* to validate the token — that happens upstream in the security stack (Elytron) before the enforcer ever sees it. My lab only let an `alg:none` token through because the lab itself skipped that layer. In a real deployment it never reaches the enforcer. *Won't fix.* Fair.
- **`keycloak.json` interpolates `${env.X}`.** Also true, also not a boundary: anyone who can edit that file on the classpath can already run arbitrary code in the same JVM and call `System.getenv()` directly. Reading env vars buys an attacker nothing they didn't already have. *Won't fix.* Also fair.

That's a 1-in-3 hit rate, and I think that's a healthy ratio to publish. The skill in vulnerability research isn't only finding a weird code path — it's correctly arguing whether a weird code path actually crosses a privilege boundary. The two dismissals taught me as much as the accept did.

The one that landed, the `.contains()` bypass, was acknowledged the same day I reported it and triaged as a real authorization bypass. I asked for credit and got it. Then it sat — as accepted vulns do — until the fix shipped and the advisory went public on 2026-06-26 as CVE-2026-9800.

## Timeline

- **2026-05-16** — Found and reproduced end-to-end in a local lab. Reported all three findings privately to the Keycloak security team. The `.contains()` bypass acknowledged the same afternoon.
- **~2026-05-22** — Findings 1 and 3 dismissed as working-as-designed (with reasoning I agree with).
- **2026-06-26** — Fix released in 26.6.4 / 26.0.10; advisory GHSA-f5p5-6xmx-p252 / CVE-2026-9800 published.

## A note on the journey

This was the first thing I ever pointed an AI at and said "find me a critical bug." Okay — it wasn't *exactly* that easy, but it wasn't far off either, if you know the jargon. First package, first audit, first try — and it worked, which I want to be clear was lucky as much as anything. A lot of audits since have closed with no finding at all; that's the normal outcome, and it's the reason a first-try hit felt like winning a coin flip.

What the model is genuinely good at is reading a large unfamiliar codebase fast and flagging the spots where the check and the decision drift apart — a `contains` where you'd expect an `equals`, a fallback that fails open.

*Reported by Bas Levering, independent. Thanks to the Keycloak security team for an acknowledgement and a clean back-port.*
