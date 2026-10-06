# Rule reference

<!-- Generated from src/rules/catalog.ts by scripts/gen-rules.ts. Do not edit by hand. -->

194 deterministic rules across 10 agents. Every finding links here by id.

| Agent | Rules |
| --- | --- |
| Recon | [RECON-L01](#recon-l01) |
| SecretsHunter | [SEC-001](#sec-001) [SEC-002](#sec-002) [SEC-003](#sec-003) [SEC-004](#sec-004) [SEC-005](#sec-005) [SEC-006](#sec-006) [SEC-007](#sec-007) [SEC-008](#sec-008) [SEC-009](#sec-009) [SEC-010](#sec-010) [SEC-011](#sec-011) [SEC-012](#sec-012) [SEC-013](#sec-013) [SEC-014](#sec-014) [SEC-015](#sec-015) [SEC-016](#sec-016) [SEC-017](#sec-017) [SEC-018](#sec-018) [SEC-019](#sec-019) [SEC-020](#sec-020) [SEC-021](#sec-021) [SEC-022](#sec-022) [SEC-023](#sec-023) [SEC-024](#sec-024) [SEC-025](#sec-025) [SEC-026](#sec-026) [SEC-027](#sec-027) [SEC-028](#sec-028) [SEC-029](#sec-029) [SEC-030](#sec-030) [SEC-031](#sec-031) [SEC-032](#sec-032) [SEC-033](#sec-033) [SEC-034](#sec-034) [SEC-035](#sec-035) [SEC-036](#sec-036) [SEC-037](#sec-037) [SEC-038](#sec-038) [SEC-039](#sec-039) [SEC-040](#sec-040) [SEC-041](#sec-041) [SEC-042](#sec-042) [SEC-043](#sec-043) [SEC-044](#sec-044) [SEC-045](#sec-045) [SEC-046](#sec-046) [SEC-047](#sec-047) [SEC-048](#sec-048) [SEC-049](#sec-049) [SEC-050](#sec-050) [SEC-051](#sec-051) [SEC-052](#sec-052) [SEC-053](#sec-053) [SEC-054](#sec-054) [SEC-055](#sec-055) [SEC-056](#sec-056) [SEC-057](#sec-057) [SEC-058](#sec-058) [SEC-059](#sec-059) [SEC-090](#sec-090) [SEC-100](#sec-100) [SEC-101](#sec-101) [SEC-102](#sec-102) [SEC-L01](#sec-l01) [SEC-110](#sec-110) [SEC-111](#sec-111) [SEC-112](#sec-112) |
| DatabaseGuard | [DB-001](#db-001) [DB-002](#db-002) [DB-003](#db-003) [DB-004](#db-004) [DB-005](#db-005) [DB-006](#db-006) [DB-007](#db-007) [DB-010](#db-010) [DB-011](#db-011) [DB-012](#db-012) [DB-013](#db-013) [DB-014](#db-014) [DB-015](#db-015) [DB-016](#db-016) [DB-017](#db-017) [DB-018](#db-018) [DB-019](#db-019) [DB-020](#db-020) [DB-021](#db-021) [DB-022](#db-022) [DB-L01](#db-l01) [DB-L02](#db-l02) |
| AuthAuditor | [AUTH-001](#auth-001) [AUTH-002](#auth-002) [AUTH-003](#auth-003) [AUTH-004](#auth-004) [AUTH-005](#auth-005) [AUTH-006](#auth-006) [AUTH-007](#auth-007) [AUTH-008](#auth-008) [AUTH-009](#auth-009) [AUTH-010](#auth-010) [AUTH-011](#auth-011) [AUTH-012](#auth-012) [AUTH-013](#auth-013) [AUTH-014](#auth-014) [AUTH-015](#auth-015) [AUTH-016](#auth-016) [AUTH-017](#auth-017) [AUTH-018](#auth-018) [AUTH-019](#auth-019) |
| WebHardener | [WEB-001](#web-001) [WEB-002](#web-002) [WEB-003](#web-003) [WEB-004](#web-004) [WEB-006](#web-006) [WEB-007](#web-007) [WEB-008](#web-008) [WEB-009](#web-009) [WEB-010](#web-010) [WEB-011](#web-011) [WEB-L01](#web-l01) [WEB-L02](#web-l02) [WEB-L03](#web-l03) [WEB-L04](#web-l04) [WEB-L05](#web-l05) [WEB-L06](#web-l06) [WEB-L07](#web-l07) [WEB-L08](#web-l08) [WEB-L09](#web-l09) [WEB-L10](#web-l10) [WEB-L11](#web-l11) |
| SupplyChain | [SUP-000](#sup-000) [SUP-001](#sup-001) [SUP-002](#sup-002) [SUP-003](#sup-003) [SUP-004](#sup-004) [SUP-005](#sup-005) [SUP-006](#sup-006) [SUP-008](#sup-008) [SUP-009](#sup-009) [SUP-010](#sup-010) [SUP-011](#sup-011) [SUP-012](#sup-012) [SUP-013](#sup-013) [SUP-014](#sup-014) [SUP-015](#sup-015) [SUP-016](#sup-016) [SUP-017](#sup-017) [SUP-018](#sup-018) [SUP-019](#sup-019) [SUP-020](#sup-020) |
| AIGuard | [AI-001](#ai-001) [AI-002](#ai-002) [AI-003](#ai-003) [AI-004](#ai-004) [AI-005](#ai-005) [AI-006](#ai-006) [AI-007](#ai-007) [AI-008](#ai-008) [AI-009](#ai-009) [AI-010](#ai-010) |
| InjectionHunter | [INJ-001](#inj-001) [INJ-002](#inj-002) [INJ-003](#inj-003) [INJ-004](#inj-004) [INJ-005](#inj-005) [INJ-006](#inj-006) [INJ-007](#inj-007) [INJ-008](#inj-008) [INJ-009](#inj-009) [INJ-010](#inj-010) |
| PyGuard | [PY-001](#py-001) [PY-002](#py-002) [PY-003](#py-003) [PY-004](#py-004) [PY-005](#py-005) [PY-006](#py-006) [PY-007](#py-007) [PY-008](#py-008) [PY-009](#py-009) [PY-010](#py-010) [PY-011](#py-011) [PY-012](#py-012) [PY-013](#py-013) [PY-014](#py-014) [PY-015](#py-015) |
| AI review (opt-in, whsquad review) | [REV-001](#rev-001) [REV-002](#rev-002) [REV-003](#rev-003) [REV-004](#rev-004) [REV-005](#rev-005) [REV-006](#rev-006) [REV-007](#rev-007) [REV-008](#rev-008) [REV-009](#rev-009) |

## Recon

| Id | Title | Severity |
| --- | --- | --- |
| [RECON-L01](#recon-l01) | Backend exposed to the browser | info |

### RECON-L01

**Backend exposed to the browser** — info · CWE-200 · OWASP A05 · modes: live

The site ships connection details for a Supabase or Firebase backend in its public JavaScript. This is normal because anon keys and Firebase config are public by design, but it means anyone can talk to the backend directly, so RLS or security rules are the only real protection.

**Fix:** Make sure Row Level Security or Firebase security rules are enabled and restrictive on every table or collection, and never ship the service_role key.

## SecretsHunter

| Id | Title | Severity |
| --- | --- | --- |
| [SEC-001](#sec-001) | Hardcoded AWS access key ID | critical |
| [SEC-002](#sec-002) | Hardcoded AWS secret access key | critical |
| [SEC-003](#sec-003) | Hardcoded Google Cloud service-account private key | critical |
| [SEC-004](#sec-004) | Hardcoded Stripe live secret key | critical |
| [SEC-005](#sec-005) | Hardcoded Stripe webhook signing secret | high |
| [SEC-006](#sec-006) | Hardcoded OpenRouter API key | high |
| [SEC-007](#sec-007) | Hardcoded Anthropic API key | high |
| [SEC-008](#sec-008) | Hardcoded OpenAI API key | high |
| [SEC-009](#sec-009) | Hardcoded Supabase service_role key | critical |
| [SEC-010](#sec-010) | Hardcoded GitHub token | critical |
| [SEC-011](#sec-011) | Hardcoded GitHub fine-grained personal access token | critical |
| [SEC-012](#sec-012) | Hardcoded Slack token | high |
| [SEC-013](#sec-013) | Hardcoded Slack webhook URL | medium |
| [SEC-014](#sec-014) | Hardcoded Twilio API key | high |
| [SEC-015](#sec-015) | Hardcoded Twilio auth token | high |
| [SEC-016](#sec-016) | Hardcoded SendGrid API key | high |
| [SEC-017](#sec-017) | Hardcoded Mailgun API key | high |
| [SEC-018](#sec-018) | Hardcoded Resend API key | high |
| [SEC-019](#sec-019) | Hardcoded Postmark server token | high |
| [SEC-020](#sec-020) | Hardcoded Discord bot token | high |
| [SEC-021](#sec-021) | Hardcoded Discord webhook URL | medium |
| [SEC-022](#sec-022) | Hardcoded Telegram bot token | high |
| [SEC-023](#sec-023) | Hardcoded Hugging Face token | high |
| [SEC-024](#sec-024) | Hardcoded Replicate API token | high |
| [SEC-025](#sec-025) | Hardcoded Groq API key | high |
| [SEC-026](#sec-026) | Hardcoded Mistral API key | high |
| [SEC-027](#sec-027) | Hardcoded Cohere API key | high |
| [SEC-028](#sec-028) | Hardcoded Pinecone API key | high |
| [SEC-029](#sec-029) | Hardcoded Clerk secret key | high |
| [SEC-030](#sec-030) | Hardcoded Private key (PEM) | critical |
| [SEC-031](#sec-031) | Hardcoded PostgreSQL connection string with password | critical |
| [SEC-032](#sec-032) | Hardcoded MongoDB connection string with password | critical |
| [SEC-033](#sec-033) | Hardcoded Redis connection string with password | high |
| [SEC-034](#sec-034) | Hardcoded npm access token | critical |
| [SEC-035](#sec-035) | Hardcoded Vercel token | high |
| [SEC-036](#sec-036) | Hardcoded Netlify personal access token | high |
| [SEC-037](#sec-037) | Hardcoded Algolia admin API key | high |
| [SEC-038](#sec-038) | Hardcoded Mapbox secret token | medium |
| [SEC-039](#sec-039) | Hardcoded Shopify access token | critical |
| [SEC-040](#sec-040) | Hardcoded Square access token | critical |
| [SEC-041](#sec-041) | Hardcoded DigitalOcean token | critical |
| [SEC-042](#sec-042) | Hardcoded Linear API key | medium |
| [SEC-043](#sec-043) | Hardcoded Sentry auth token | medium |
| [SEC-044](#sec-044) | Hardcoded Doppler token | critical |
| [SEC-045](#sec-045) | Hardcoded PlanetScale token | critical |
| [SEC-046](#sec-046) | Hardcoded Databricks token | high |
| [SEC-047](#sec-047) | Hardcoded Perplexity API key | high |
| [SEC-048](#sec-048) | Hardcoded xAI API key | high |
| [SEC-049](#sec-049) | Hardcoded MySQL connection string with password | critical |
| [SEC-050](#sec-050) | Hardcoded Supabase secret API key | critical |
| [SEC-051](#sec-051) | Hardcoded Supabase personal access token | critical |
| [SEC-052](#sec-052) | Hardcoded Google OAuth client secret | high |
| [SEC-053](#sec-053) | Hardcoded Upstash Redis REST token | high |
| [SEC-054](#sec-054) | Hardcoded Neon API key | high |
| [SEC-055](#sec-055) | Hardcoded Render API key | high |
| [SEC-056](#sec-056) | Hardcoded Fly.io access token | high |
| [SEC-057](#sec-057) | Hardcoded Brevo (Sendinblue) API key | high |
| [SEC-058](#sec-058) | Hardcoded Lemon Squeezy API key | high |
| [SEC-059](#sec-059) | Hardcoded Google AI (Gemini) API key | high |
| [SEC-090](#sec-090) | High-entropy secret-like value | medium |
| [SEC-100](#sec-100) | Environment file is not git-ignored | high |
| [SEC-101](#sec-101) | Secret placed in a public browser-exposed variable | critical |
| [SEC-102](#sec-102) | Secret remains in git history | critical |
| [SEC-L01](#sec-l01) | Secret exposed in the live site | critical |
| [SEC-110](#sec-110) | Weak or hardcoded fallback application secret | high |
| [SEC-111](#sec-111) | Literal secret in compose, workflow, Dockerfile or properties file | medium |
| [SEC-112](#sec-112) | Dockerfile copies the whole build context without excluding .env | medium |

### SEC-001

**Hardcoded AWS access key ID** — critical · CWE-798 · OWASP A07 · modes: static

A AWS access key ID is written into source or config. Anyone who can read the code can copy it and spin up servers, read S3 buckets and databases, and run up a cloud bill. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-002

**Hardcoded AWS secret access key** — critical · CWE-798 · OWASP A07 · modes: static

A AWS secret access key is written into source or config. Anyone who can read the code can copy it and spin up servers, read S3 buckets and databases, and run up a cloud bill. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-003

**Hardcoded Google Cloud service-account private key** — critical · CWE-798 · OWASP A07 · modes: static

A Google Cloud service-account private key is written into source or config. Anyone who can read the code can copy it and act as your service account: read storage, databases and anything it has roles for. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-004

**Hardcoded Stripe live secret key** — critical · CWE-798 · OWASP A07 · modes: static

A Stripe live secret key is written into source or config. Anyone who can read the code can copy it and create charges and refunds, read customer and card metadata, and move your money. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-005

**Hardcoded Stripe webhook signing secret** — high · CWE-798 · OWASP A07 · modes: static

A Stripe webhook signing secret is written into source or config. Anyone who can read the code can copy it and forge payment webhooks so your app believes an unpaid order was paid. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-006

**Hardcoded OpenRouter API key** — high · CWE-798 · OWASP A07 · modes: static

A OpenRouter API key is written into source or config. Anyone who can read the code can copy it and burn through your AI credits. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-007

**Hardcoded Anthropic API key** — high · CWE-798 · OWASP A07 · modes: static

A Anthropic API key is written into source or config. Anyone who can read the code can copy it and burn through your AI credits. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-008

**Hardcoded OpenAI API key** — high · CWE-798 · OWASP A07 · modes: static

A OpenAI API key is written into source or config. Anyone who can read the code can copy it and burn through your AI credits. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-009

**Hardcoded Supabase service_role key** — critical · CWE-798 · OWASP A07 · modes: static

A Supabase service_role key is written into source or config. Anyone who can read the code can copy it and bypass every Row Level Security policy and read, edit or delete your whole database. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-010

**Hardcoded GitHub token** — critical · CWE-798 · OWASP A07 · modes: static

A GitHub token is written into source or config. Anyone who can read the code can copy it and read or push to your private repositories. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-011

**Hardcoded GitHub fine-grained personal access token** — critical · CWE-798 · OWASP A07 · modes: static

A GitHub fine-grained personal access token is written into source or config. Anyone who can read the code can copy it and read or push to your private repositories. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-012

**Hardcoded Slack token** — high · CWE-798 · OWASP A07 · modes: static

A Slack token is written into source or config. Anyone who can read the code can copy it and read your workspace messages and post as your bot. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-013

**Hardcoded Slack webhook URL** — medium · CWE-798 · OWASP A07 · modes: static

A Slack webhook URL is written into source or config. Anyone who can read the code can copy it and post any message into your Slack channel. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-014

**Hardcoded Twilio API key** — high · CWE-798 · OWASP A07 · modes: static

A Twilio API key is written into source or config. Anyone who can read the code can copy it and send SMS and place calls on your bill. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-015

**Hardcoded Twilio auth token** — high · CWE-798 · OWASP A07 · modes: static

A Twilio auth token is written into source or config. Anyone who can read the code can copy it and send SMS and place calls on your bill. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-016

**Hardcoded SendGrid API key** — high · CWE-798 · OWASP A07 · modes: static

A SendGrid API key is written into source or config. Anyone who can read the code can copy it and send phishing email from your domain. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-017

**Hardcoded Mailgun API key** — high · CWE-798 · OWASP A07 · modes: static

A Mailgun API key is written into source or config. Anyone who can read the code can copy it and send phishing email from your domain. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-018

**Hardcoded Resend API key** — high · CWE-798 · OWASP A07 · modes: static

A Resend API key is written into source or config. Anyone who can read the code can copy it and send phishing email from your domain. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-019

**Hardcoded Postmark server token** — high · CWE-798 · OWASP A07 · modes: static

A Postmark server token is written into source or config. Anyone who can read the code can copy it and send phishing email from your domain. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-020

**Hardcoded Discord bot token** — high · CWE-798 · OWASP A07 · modes: static

A Discord bot token is written into source or config. Anyone who can read the code can copy it and take over your bot and every server it is in. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-021

**Hardcoded Discord webhook URL** — medium · CWE-798 · OWASP A07 · modes: static

A Discord webhook URL is written into source or config. Anyone who can read the code can copy it and post any message into your Discord channel. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-022

**Hardcoded Telegram bot token** — high · CWE-798 · OWASP A07 · modes: static

A Telegram bot token is written into source or config. Anyone who can read the code can copy it and take over your bot and read its messages. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-023

**Hardcoded Hugging Face token** — high · CWE-798 · OWASP A07 · modes: static

A Hugging Face token is written into source or config. Anyone who can read the code can copy it and read your private models and push to your repos. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-024

**Hardcoded Replicate API token** — high · CWE-798 · OWASP A07 · modes: static

A Replicate API token is written into source or config. Anyone who can read the code can copy it and run models on your bill. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-025

**Hardcoded Groq API key** — high · CWE-798 · OWASP A07 · modes: static

A Groq API key is written into source or config. Anyone who can read the code can copy it and burn through your AI quota. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-026

**Hardcoded Mistral API key** — high · CWE-798 · OWASP A07 · modes: static

A Mistral API key is written into source or config. Anyone who can read the code can copy it and burn through your AI credits. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-027

**Hardcoded Cohere API key** — high · CWE-798 · OWASP A07 · modes: static

A Cohere API key is written into source or config. Anyone who can read the code can copy it and burn through your AI credits. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-028

**Hardcoded Pinecone API key** — high · CWE-798 · OWASP A07 · modes: static

A Pinecone API key is written into source or config. Anyone who can read the code can copy it and read, overwrite or delete your vector indexes. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-029

**Hardcoded Clerk secret key** — high · CWE-798 · OWASP A07 · modes: static

A Clerk secret key is written into source or config. Anyone who can read the code can copy it and list, impersonate and delete your users. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-030

**Hardcoded Private key (PEM)** — critical · CWE-798 · OWASP A07 · modes: static

A Private key (PEM) is written into source or config. Anyone who can read the code can copy it and impersonate your server or sign things as you. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-031

**Hardcoded PostgreSQL connection string with password** — critical · CWE-798 · OWASP A07 · modes: static

A PostgreSQL connection string with password is written into source or config. Anyone who can read the code can copy it and connect straight to your database and read, change or wipe everything. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-032

**Hardcoded MongoDB connection string with password** — critical · CWE-798 · OWASP A07 · modes: static

A MongoDB connection string with password is written into source or config. Anyone who can read the code can copy it and connect straight to your database and read, change or wipe everything. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-033

**Hardcoded Redis connection string with password** — high · CWE-798 · OWASP A07 · modes: static

A Redis connection string with password is written into source or config. Anyone who can read the code can copy it and read your cache and sessions, or flush them. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-034

**Hardcoded npm access token** — critical · CWE-798 · OWASP A07 · modes: static

A npm access token is written into source or config. Anyone who can read the code can copy it and publish a malicious version of your packages. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-035

**Hardcoded Vercel token** — high · CWE-798 · OWASP A07 · modes: static

A Vercel token is written into source or config. Anyone who can read the code can copy it and deploy to and read the env vars of your projects. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-036

**Hardcoded Netlify personal access token** — high · CWE-798 · OWASP A07 · modes: static

A Netlify personal access token is written into source or config. Anyone who can read the code can copy it and deploy to and read the env vars of your sites. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-037

**Hardcoded Algolia admin API key** — high · CWE-798 · OWASP A07 · modes: static

A Algolia admin API key is written into source or config. Anyone who can read the code can copy it and edit or delete your search indexes. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-038

**Hardcoded Mapbox secret token** — medium · CWE-798 · OWASP A07 · modes: static

A Mapbox secret token is written into source or config. Anyone who can read the code can copy it and use your Mapbox quota and edit your map data. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-039

**Hardcoded Shopify access token** — critical · CWE-798 · OWASP A07 · modes: static

A Shopify access token is written into source or config. Anyone who can read the code can copy it and read orders and customers, and change your store. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-040

**Hardcoded Square access token** — critical · CWE-798 · OWASP A07 · modes: static

A Square access token is written into source or config. Anyone who can read the code can copy it and take payments and read customer data. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-041

**Hardcoded DigitalOcean token** — critical · CWE-798 · OWASP A07 · modes: static

A DigitalOcean token is written into source or config. Anyone who can read the code can copy it and create, read and destroy your servers and databases. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-042

**Hardcoded Linear API key** — medium · CWE-798 · OWASP A07 · modes: static

A Linear API key is written into source or config. Anyone who can read the code can copy it and read and edit your issue tracker. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-043

**Hardcoded Sentry auth token** — medium · CWE-798 · OWASP A07 · modes: static

A Sentry auth token is written into source or config. Anyone who can read the code can copy it and read your error reports and project settings. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-044

**Hardcoded Doppler token** — critical · CWE-798 · OWASP A07 · modes: static

A Doppler token is written into source or config. Anyone who can read the code can copy it and read every secret stored in that Doppler project. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-045

**Hardcoded PlanetScale token** — critical · CWE-798 · OWASP A07 · modes: static

A PlanetScale token is written into source or config. Anyone who can read the code can copy it and connect to your database and read or change everything. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-046

**Hardcoded Databricks token** — high · CWE-798 · OWASP A07 · modes: static

A Databricks token is written into source or config. Anyone who can read the code can copy it and run jobs and read data in your workspace. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-047

**Hardcoded Perplexity API key** — high · CWE-798 · OWASP A07 · modes: static

A Perplexity API key is written into source or config. Anyone who can read the code can copy it and burn through your AI credits. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-048

**Hardcoded xAI API key** — high · CWE-798 · OWASP A07 · modes: static

A xAI API key is written into source or config. Anyone who can read the code can copy it and burn through your AI credits. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-049

**Hardcoded MySQL connection string with password** — critical · CWE-798 · OWASP A07 · modes: static

A MySQL connection string with password is written into source or config. Anyone who can read the code can copy it and connect straight to your database and read, change or wipe everything. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-050

**Hardcoded Supabase secret API key** — critical · CWE-798 · OWASP A07 · modes: static

A Supabase secret API key is written into source or config. Anyone who can read the code can copy it and bypass every Row Level Security policy and read, edit or delete your whole database. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-051

**Hardcoded Supabase personal access token** — critical · CWE-798 · OWASP A07 · modes: static

A Supabase personal access token is written into source or config. Anyone who can read the code can copy it and manage every project in your Supabase account through the management API. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-052

**Hardcoded Google OAuth client secret** — high · CWE-798 · OWASP A07 · modes: static

A Google OAuth client secret is written into source or config. Anyone who can read the code can copy it and impersonate your app in Google sign-in and exchange stolen authorization codes. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-053

**Hardcoded Upstash Redis REST token** — high · CWE-798 · OWASP A07 · modes: static

A Upstash Redis REST token is written into source or config. Anyone who can read the code can copy it and read, overwrite or flush your Redis data. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-054

**Hardcoded Neon API key** — high · CWE-798 · OWASP A07 · modes: static

A Neon API key is written into source or config. Anyone who can read the code can copy it and create, change and delete your Neon projects and databases. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-055

**Hardcoded Render API key** — high · CWE-798 · OWASP A07 · modes: static

A Render API key is written into source or config. Anyone who can read the code can copy it and deploy to, read the env vars of and delete your Render services. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-056

**Hardcoded Fly.io access token** — high · CWE-798 · OWASP A07 · modes: static

A Fly.io access token is written into source or config. Anyone who can read the code can copy it and deploy to and read the secrets of your Fly.io apps. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-057

**Hardcoded Brevo (Sendinblue) API key** — high · CWE-798 · OWASP A07 · modes: static

A Brevo (Sendinblue) API key is written into source or config. Anyone who can read the code can copy it and send phishing email from your domain and read your contact lists. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-058

**Hardcoded Lemon Squeezy API key** — high · CWE-798 · OWASP A07 · modes: static

A Lemon Squeezy API key is written into source or config. Anyone who can read the code can copy it and read your orders and customers and change your store and subscriptions. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-059

**Hardcoded Google AI (Gemini) API key** — high · CWE-798 · OWASP A07 · modes: static

A Google AI (Gemini) API key is written into source or config. Anyone who can read the code can copy it and burn through your AI quota and bill. Deleting the line does not undo exposure because the value stays in git history and build logs.

**Fix:** Rotate the credential at the provider first, then load the replacement from a server-side environment variable or secret manager. Never ship it in client code or a public-prefixed variable.

### SEC-090

**High-entropy secret-like value** — medium · CWE-798 · OWASP A07 · modes: static

A long, random-looking string is assigned to a variable named like a key, secret, token or password. This is a heuristic match at low confidence; if the value is a real credential it is exposed to everyone who can read the code. Public key shapes (Firebase web keys, publishable keys) are excluded.

**Fix:** Confirm whether the value is a real credential. If so, rotate it and load it from a server-side environment variable.

### SEC-100

**Environment file is not git-ignored** — high · CWE-538 · OWASP A02 · modes: static

A .env file with private values is in the repository and nothing in .gitignore stops it being committed. Everyone with repository access can read every value, and committed values live on in history.

**Fix:** Add .env and .env.* (except .env.example) to .gitignore, stop tracking the file with git rm --cached, and rotate every value it contained.

### SEC-101

**Secret placed in a public browser-exposed variable** — critical · CWE-200 · OWASP A02 · modes: static

A real secret is stored in a variable whose prefix (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ and similar) makes the build tool copy it into the JavaScript bundle. Every visitor can read it from the browser.

**Fix:** Remove the public prefix, rotate the secret, and move every use behind a server-side route or edge function.

### SEC-102

**Secret remains in git history** — critical · CWE-798 · OWASP A07 · modes: static

A credential was committed and later removed, but it is still recoverable from git history by anyone with a clone or fork. Removing the line did not revoke it.

**Fix:** Treat the secret as stolen and rotate it. Optionally rewrite history with git filter-repo or BFG; rotation matters more than the rewrite.

### SEC-L01

**Secret exposed in the live site** — critical · CWE-798 · OWASP A02 · modes: live

A secret-class credential is served to every visitor in the live page or its scripts. Anyone can copy it from the page source with no login.

**Fix:** Rotate the credential immediately, remove it from the client bundle, and call the service from server-side code instead.

### SEC-110

**Weak or hardcoded fallback application secret** — high · CWE-798 · OWASP A07 · modes: static

JWT_SECRET, NEXTAUTH_SECRET, AUTH_SECRET, SESSION_SECRET, COOKIE_SECRET, APP_SECRET, SECRET_KEY or ENCRYPTION_KEY is a short or well-known literal, or has a literal fallback such as process.env.JWT_SECRET || "fallback". Anyone who knows or guesses it can forge sessions and tokens for any user. Placeholders in .env.example are not reported.

**Fix:** Generate a random value of at least 32 bytes, keep it only in environment settings, read it with no fallback and fail at startup if it is missing.

### SEC-111

**Literal secret in compose, workflow, Dockerfile or properties file** — medium · CWE-798 · OWASP A07 · modes: static

A secret-named variable in docker-compose environment blocks, GitHub Actions env blocks, Dockerfile ENV/ARG or a .properties file holds a literal value instead of a reference. These files are committed, and Dockerfile values persist in image layers. References such as ${VAR} and ${{ secrets.X }} are not reported.

**Fix:** Reference the value by name from a secret store or gitignored .env, use build secrets in Dockerfiles, and rotate the value if it is real.

### SEC-112

**Dockerfile copies the whole build context without excluding .env** — medium · CWE-538 · OWASP A05 · modes: static

A Dockerfile runs COPY . . (or ADD . .) and no .dockerignore excludes .env files, so the .env with real credentials is baked into an image layer that anyone able to pull the image can read.

**Fix:** Add a .dockerignore excluding .env, .env.*, .git and node_modules, or copy only the paths the build needs; rotate secrets if an old image was pushed.

## DatabaseGuard

| Id | Title | Severity |
| --- | --- | --- |
| [DB-001](#db-001) | Table without Row Level Security | critical |
| [DB-002](#db-002) | RLS enabled but no policies | low |
| [DB-003](#db-003) | Policy allows everyone (USING true) | high |
| [DB-004](#db-004) | Policy never checks who the user is | medium |
| [DB-005](#db-005) | SECURITY DEFINER function without fixed search_path | high |
| [DB-006](#db-006) | Write privileges granted to anon | high |
| [DB-007](#db-007) | Public storage bucket | medium |
| [DB-010](#db-010) | Firebase Firestore / Realtime Database rules open to everyone | critical |
| [DB-011](#db-011) | Firebase Cloud Storage rules open to everyone | critical |
| [DB-012](#db-012) | Authorization based on user_metadata | critical |
| [DB-013](#db-013) | Users can edit their own privilege columns | high |
| [DB-014](#db-014) | SECURITY DEFINER function callable by anon/authenticated | high |
| [DB-015](#db-015) | View bypasses RLS or exposes auth.users | high |
| [DB-016](#db-016) | Policies exist but RLS is never enabled | high |
| [DB-017](#db-017) | Policy only requires a signed-in user | medium |
| [DB-018](#db-018) | Unsafe storage.objects policy | high |
| [DB-019](#db-019) | Sensitive columns exposed by a broad read policy | high |
| [DB-020](#db-020) | Edge Function with verify_jwt = false and no own authentication | high |
| [DB-021](#db-021) | Anonymous sign-ins reach 'to authenticated' policies | high |
| [DB-022](#db-022) | Firebase rules only require sign-in on a wildcard path | high |
| [DB-L01](#db-l01) | Supabase table readable with the public key (live) | critical |
| [DB-L02](#db-l02) | Firestore collection readable without sign-in (live) | critical |

### DB-001

**Table without Row Level Security** — critical · CWE-862 · OWASP A01 · modes: static

A table in the public schema never has Row Level Security enabled. Supabase exposes public tables through its REST API and the anon key ships in the frontend, so anyone can read, change or delete every row.

**Fix:** ALTER TABLE ... ENABLE ROW LEVEL SECURITY and add owner-scoped policies using (select auth.uid()).

### DB-002

**RLS enabled but no policies** — low · CWE-284 · OWASP A01 · modes: static

RLS is enabled on a table that has no policy, so only the service role can use it. The setup is unfinished and may later be 'fixed' with a wide-open policy.

**Fix:** Add explicit owner-scoped policies for each operation the app needs.

### DB-003

**Policy allows everyone (USING true)** — high · CWE-862 · OWASP A01 · modes: static

A permissive policy uses USING (true) or WITH CHECK (true) for anon, authenticated or public on a table that holds user data. Every row is readable or writable by anyone in those roles. Restrictive policies are ignored because they only narrow access.

**Fix:** Drop the policy and replace it with one comparing auth.uid() to the owner column.

### DB-004

**Policy never checks who the user is** — medium · CWE-284 · OWASP A01 · modes: static

A policy on a table with an owner column never references auth.uid() or auth.jwt(), so it cannot tell users apart and signed-in users may reach each other's rows.

**Fix:** Scope the policy to (select auth.uid()) = <owner column>.

### DB-005

**SECURITY DEFINER function without fixed search_path** — high · CWE-269 · OWASP A01 · modes: static

A SECURITY DEFINER function runs with its owner's privileges but does not pin search_path, so a user who can create objects in an earlier schema can hijack what it calls and escalate privileges.

**Fix:** Add SET search_path = '' to the function and schema-qualify every object inside it.

### DB-006

**Write privileges granted to anon** — high · CWE-284 · OWASP A01 · modes: static

A GRANT gives INSERT/UPDATE/DELETE/TRUNCATE (or ALL) on tables to the anon role, which anyone with the public key can use. Any RLS gap then becomes an unauthenticated write.

**Fix:** REVOKE the write privileges from anon and rely on RLS policies for authenticated users.

### DB-007

**Public storage bucket** — medium · CWE-284 · OWASP A01 · modes: static

A storage bucket (from SQL or supabase/config.toml) is public, so every file is downloadable by anyone who has or guesses the URL. That is fine for logos but not for avatars, documents or receipts.

**Fix:** Make the bucket private, store files under a <user id>/ prefix, add owner-scoped storage policies and serve signed URLs.

### DB-010

**Firebase Firestore / Realtime Database rules open to everyone** — critical · CWE-284 · OWASP A01 · modes: static

Firestore or Realtime Database rules allow reads or writes to anyone (if true) or only until a test-mode expiry date. Once the date has passed the rule is reported at medium severity: the database is closed now but was open, and the usual panic fix reopens it.

**Fix:** Require request.auth != null plus an ownership check (request.auth.uid == userId) and remove 'if true' and request.time expiries.

### DB-011

**Firebase Cloud Storage rules open to everyone** — critical · CWE-284 · OWASP A01 · modes: static

Cloud Storage rules allow anyone, signed in or not, to read or write every file, or keep that access open until a test-mode expiry date.

**Fix:** Restrict storage rules to the signed-in owner's own folder and remove 'if true' and expiry dates.

### DB-012

**Authorization based on user_metadata** — critical · CWE-639 · OWASP A01 · modes: static

A policy or SECURITY DEFINER role check reads user_metadata / raw_user_meta_data, which the signed-in user can edit themselves (Supabase linter 0015). Any user can grant themselves admin. app_metadata is the safe alternative and is never flagged.

**Fix:** Use app_metadata (server-written) or a roles table that users cannot write.

### DB-013

**Users can edit their own privilege columns** — high · CWE-269 · OWASP A01 · modes: static

A table has a column such as role, is_admin, credits, plan or balance and an own-row UPDATE policy without column protection. Any user can call the API and set those columns on their own row. High for role/admin columns, medium for credits, plan and billing columns.

**Fix:** REVOKE UPDATE on the table and GRANT UPDATE only on the columns users may edit, or guard the column with a BEFORE UPDATE trigger.

### DB-014

**SECURITY DEFINER function callable by anon/authenticated** — high · CWE-862 · OWASP A01 · modes: static

A SECURITY DEFINER function in the public schema is never revoked from anon/authenticated, so anyone can call it through /rest/v1/rpc with the public key and bypass RLS (Supabase linter 0028/0029). It is worse when it takes a uuid and never checks auth.uid().

**Fix:** REVOKE EXECUTE from public, anon and authenticated, or check auth.uid() inside and move it out of the exposed schema.

### DB-015

**View bypasses RLS or exposes auth.users** — high · CWE-284 · OWASP A01 · modes: static

A view in the public schema lacks security_invoker, so it runs with its owner's rights and bypasses RLS on the tables it reads (linter 0010). It is critical when it selects from auth.users (linter 0002).

**Fix:** ALTER VIEW ... SET (security_invoker = true), or REVOKE SELECT from anon and authenticated.

### DB-016

**Policies exist but RLS is never enabled** — high · CWE-862 · OWASP A01 · modes: static

A table has policies but Row Level Security is never enabled on it, so the policies are not enforced and the table is open to anyone with the anon key (linter 0007). The author believes it is protected.

**Fix:** ALTER TABLE ... ENABLE ROW LEVEL SECURITY.

### DB-017

**Policy only requires a signed-in user** — medium · CWE-284 · OWASP A01 · modes: static

A policy on a table with an owner column only checks auth.uid() IS NOT NULL or auth.role() = 'authenticated'. Sign-up is free, so every account can reach every user's rows.

**Fix:** Compare auth.uid() to the owner column instead of only checking sign-in.

### DB-018

**Unsafe storage.objects policy** — high · CWE-862 · OWASP A01 · modes: static

A storage.objects policy lets users insert, update or delete files without an owner or folder check (high), or lets anyone list every file of a public bucket with a bare bucket_id check (medium, linter 0025).

**Fix:** Scope write policies with (storage.foldername(name))[1] = auth.uid()::text and drop SELECT policies on public buckets.

### DB-019

**Sensitive columns exposed by a broad read policy** — high · CWE-200 · OWASP A01 · modes: static

A public table has columns named like password, api_key, secret, token, otp, ssn or refresh_token and a SELECT policy for anon/authenticated without an owner check, so the secrets can be harvested through the REST API (linter 0023).

**Fix:** Revoke column access from anon/authenticated or move the secrets to a table only the service role can read.

### DB-020

**Edge Function with verify_jwt = false and no own authentication** — high · CWE-306 · OWASP A01 · modes: static

supabase/config.toml disables JWT verification for an Edge Function whose code has no auth.getUser / getClaims / jwtVerify / webhook signature / shared-secret check, so anyone can invoke it.

**Fix:** Set verify_jwt = true, or verify the caller (signature, JWT or secret) inside the function.

### DB-021

**Anonymous sign-ins reach 'to authenticated' policies** — high · CWE-287 · OWASP A01 · modes: static

Anonymous sign-ins are enabled (config.toml or signInAnonymously in code) and a policy granted 'to authenticated' neither checks is_anonymous nor ties rows to the caller, so unregistered visitors get authenticated-level access.

**Fix:** Add an is_anonymous check (a restrictive policy works) or scope the policy with auth.uid().

### DB-022

**Firebase rules only require sign-in on a wildcard path** — high · CWE-285 · OWASP A01 · modes: static

Firestore/Storage rules allow request.auth != null (or RTDB auth != null) on a wildcard match or at the database root. Sign-up is public, so 'logged in' means anyone, and every user's data is readable or writable.

**Fix:** Compare request.auth.uid with the owner (path variable or resource.data) on every user-data path.

### DB-L01

**Supabase table readable with the public key (live)** — critical · CWE-862 · OWASP A01 · modes: live

A live read-only probe using only the anon key returned a row from a table, proving anyone can download it. Only table and column names are recorded.

**Fix:** Enable RLS on the table and add owner-scoped policies.

### DB-L02

**Firestore collection readable without sign-in (live)** — critical · CWE-284 · OWASP A01 · modes: live

A live read-only request returned a document from a Firestore collection without authentication. Only collection and field names are recorded.

**Fix:** Require request.auth != null and ownership checks in firestore.rules, then deploy them.

## AuthAuditor

| Id | Title | Severity |
| --- | --- | --- |
| [AUTH-001](#auth-001) | Route protection exists only in the browser | high |
| [AUTH-002](#auth-002) | Endpoint reads or writes data without checking who is calling | high |
| [AUTH-003](#auth-003) | Record is looked up by a caller-supplied id with no ownership check (IDOR) | high |
| [AUTH-004](#auth-004) | JWT is decoded, unsigned or signed with a hard-coded secret | high |
| [AUTH-005](#auth-005) | Access decision based on a value the user controls | high |
| [AUTH-006](#auth-006) | Stripe webhook trusts the request body without verifying the signature | critical |
| [AUTH-007](#auth-007) | Supabase service_role key used in client-side code | critical |
| [AUTH-008](#auth-008) | Server code trusts supabase.auth.getSession() for authorization | high |
| [AUTH-009](#auth-009) | Authorization decision uses user_metadata, which users can edit | critical |
| [AUTH-010](#auth-010) | Request body is written straight into the database (mass assignment) | high |
| [AUTH-011](#auth-011) | Payment amount is client-controlled or a success page grants access unverified | critical |
| [AUTH-012](#auth-012) | Secret token generated with a predictable random source | high |
| [AUTH-013](#auth-013) | Weak password hashing or plaintext password handling | high |
| [AUTH-014](#auth-014) | Login or recovery endpoint has no rate limiting | medium |
| [AUTH-015](#auth-015) | Debug, seed, cron or admin route is reachable without authentication | high |
| [AUTH-016](#auth-016) | Authentication check is inverted | high |
| [AUTH-017](#auth-017) | Insecure authentication cookie, token expiry or token storage | medium |
| [AUTH-018](#auth-018) | OAuth accounts are linked by email without verification | high |
| [AUTH-019](#auth-019) | Password-reset or invite link is built from the Host header | medium |

### AUTH-001

**Route protection exists only in the browser** — high · CWE-602 · OWASP A01 · modes: static

A page redirects logged-out visitors from client-side code while the project has no middleware or server-side session check. Browser redirects are cosmetic: anyone can call the API or database directly, so the protected data is reachable without logging in.

**Fix:** Enforce the session on the server (middleware plus per-handler checks) and keep the client redirect only for UX.

### AUTH-002

**Endpoint reads or writes data without checking who is calling** — high · CWE-306 · OWASP A01 · modes: static

A route handler or server action touches the database but never checks a session or token. Any logged-out visitor can call it directly and read, change or delete other users' rows.

**Fix:** Authenticate the caller at the top of the handler, reject anonymous requests with 401, and scope queries to the authenticated user.

### AUTH-003

**Record is looked up by a caller-supplied id with no ownership check (IDOR)** — high · CWE-639 · OWASP A01 · modes: static

An id taken from the request is used to fetch, change or delete a record without checking that it belongs to the logged-in user. Any signed-in user can swap in someone else's id and read or destroy their data.

**Fix:** Filter by the authenticated user's id (for example .eq("user_id", user.id) or userId in a Prisma where clause) or rely on a correct RLS policy, and return 404 when nothing matches.

### AUTH-004

**JWT is decoded, unsigned or signed with a hard-coded secret** — high · CWE-345 · OWASP A02 · modes: static

JWT handling that does not verify the signature (jwt.decode used for authorization), accepts the none algorithm (critical), or uses a secret written in source code lets anyone forge tokens for any user or role.

**Fix:** Use jwt.verify or jose jwtVerify with a secret from the environment and a pinned algorithm allow-list that never contains none.

### AUTH-005

**Access decision based on a value the user controls** — high · CWE-602 · OWASP A01 · modes: static

A role, admin flag or plan is read from localStorage, sessionStorage or a plain cookie and used to gate access. Users can edit these in dev tools and promote themselves or unlock paid features.

**Fix:** Derive roles from the verified server-side session or a database lookup and treat client storage as display-only.

### AUTH-006

**Stripe webhook trusts the request body without verifying the signature** — critical · CWE-345 · OWASP A08 · modes: static

A webhook acts on Stripe event types after merely parsing the request body. Anyone can POST a fake checkout.session.completed event and obtain a free upgrade, credits or a paid order.

**Fix:** Read the raw body and verify it with stripe.webhooks.constructEvent and the stripe-signature header before acting; return 400 on failure.

### AUTH-007

**Supabase service_role key used in client-side code** — critical · CWE-798 · OWASP A05 · modes: static

The service_role key bypasses all Row Level Security. Code that ships to the browser exposes it, so any visitor can read, modify and delete every row in the database.

**Fix:** Use the anon key in client code, keep service_role in server-only modules, never prefix it with NEXT_PUBLIC_ or VITE_, and rotate the exposed key.

### AUTH-008

**Server code trusts supabase.auth.getSession() for authorization** — high · CWE-345 · OWASP A07 · modes: static

getSession() reads the session from the cookie and is not re-validated on the server, so a forged cookie is believed. Using session.user.id without getUser() or getClaims() in the same function lets an attacker impersonate users.

**Fix:** Call supabase.auth.getUser() (or getClaims()) on the server and authorize with that result.

### AUTH-009

**Authorization decision uses user_metadata, which users can edit** — critical · CWE-807 · OWASP A01 · modes: static

Supabase user_metadata can be changed by the signed-in user. Checking user_metadata.role, is_admin or plan in a condition lets anyone promote themselves or unlock paid features. app_metadata is safe.

**Fix:** Read roles and plans from app_metadata or a table protected by RLS.

### AUTH-010

**Request body is written straight into the database (mass assignment)** — high · CWE-915 · OWASP A01 · modes: static

The whole request object is passed to an ORM write (Prisma data, Drizzle values/set, Mongoose create/update, Supabase insert/update, Object.assign), so callers choose every column including role, is_admin, credits or user_id.

**Fix:** Validate with a schema and copy only the fields users may set.

### AUTH-011

**Payment amount is client-controlled or a success page grants access unverified** — critical · CWE-472 · OWASP A04 · modes: static

A Stripe checkout, payment intent or price is created with an amount taken from the request (critical), or a success page upgrades the account from session_id without retrieving the checkout session or relying on a webhook (high).

**Fix:** Decide prices on the server and fulfil from a verified webhook or after checkout.sessions.retrieve confirms payment.

### AUTH-012

**Secret token generated with a predictable random source** — high · CWE-338 · OWASP A02 · modes: static

Math.random() or Date.now() is used to produce a token, otp, code, secret, nonce, salt or session id in server code. These values are predictable and can be guessed.

**Fix:** Use crypto.randomBytes, crypto.randomUUID or crypto.randomInt.

### AUTH-013

**Weak password hashing or plaintext password handling** — high · CWE-916 · OWASP A02 · modes: static

Passwords hashed with md5/sha1/sha256, bcrypt with a cost below 10, compared with === or stored with no hashing are exposed when the database leaks.

**Fix:** Use bcrypt (cost 12+), argon2id or scrypt and compare with the library function.

### AUTH-014

**Login or recovery endpoint has no rate limiting** — medium · CWE-307 · OWASP A07 · modes: static

Login, signup, password reset, OTP and magic-link handlers with no rate limiter allow brute force and email flooding. Confidence is lower when a hosted auth provider throttles requests.

**Fix:** Rate limit by IP and account and return 429 when exceeded.

### AUTH-015

**Debug, seed, cron or admin route is reachable without authentication** — high · CWE-306 · OWASP A01 · modes: static

A route under debug, seed, test, dev, internal, migrate, reset-db, admin or cron has no auth check, shared secret or production guard. It is critical when it runs migrations, deletes data, executes commands or returns process.env.

**Fix:** Require an admin session or CRON_SECRET and disable debug routes in production.

### AUTH-016

**Authentication check is inverted** — high · CWE-863 · OWASP A01 · modes: static

The code returns 401/403 when a user IS present (if (user) return ...), locking out real users and letting anonymous callers through.

**Fix:** Negate the condition and test that an anonymous request gets 401.

### AUTH-017

**Insecure authentication cookie, token expiry or token storage** — medium · CWE-1004 · OWASP A07 · modes: static

Auth cookies without httpOnly or with secure off, jwt.sign without expiresIn, and tokens saved in localStorage/sessionStorage (refresh tokens are high) make session theft easier and sessions immortal.

**Fix:** Use httpOnly, secure, sameSite cookies, short token lifetimes and no web storage for tokens.

### AUTH-018

**OAuth accounts are linked by email without verification** — high · CWE-287 · OWASP A07 · modes: static

allowDangerousEmailAccountLinking: true attaches any provider sign-in to an existing account with the same email, enabling account takeover through an unverified provider email.

**Fix:** Remove the option or restrict linking to providers with verified emails.

### AUTH-019

**Password-reset or invite link is built from the Host header** — medium · CWE-640 · OWASP A07 · modes: static

A reset, invite or magic link uses a host or origin read from request headers, so an attacker can make the emailed link point at their site and capture the token.

**Fix:** Build links from a fixed site URL in configuration.

## WebHardener

| Id | Title | Severity |
| --- | --- | --- |
| [WEB-001](#web-001) | Production source maps are enabled | low |
| [WEB-002](#web-002) | CORS allows any origin to make credentialed requests | high |
| [WEB-003](#web-003) | Unsanitized value written into the page | high |
| [WEB-004](#web-004) | Next.js app does not configure security headers | low |
| [WEB-006](#web-006) | File write uses an attacker-controlled name with no sanitization | high |
| [WEB-007](#web-007) | Next.js image optimizer accepts images from any host | medium |
| [WEB-008](#web-008) | Next.js image optimizer serves SVG without a sandbox | medium |
| [WEB-009](#web-009) | Message listener does not check the sender's origin | medium |
| [WEB-010](#web-010) | Token or session data sent with postMessage to any origin | high |
| [WEB-011](#web-011) | Error details returned to clients | medium |
| [WEB-L01](#web-l01) | Content-Security-Policy header missing or weak | medium |
| [WEB-L02](#web-l02) | Strict-Transport-Security header missing or too short | low |
| [WEB-L03](#web-l03) | Clickjacking protection missing | low |
| [WEB-L04](#web-l04) | X-Content-Type-Options header missing | low |
| [WEB-L05](#web-l05) | Referrer-Policy header missing | low |
| [WEB-L06](#web-l06) | Permissions-Policy header missing | low |
| [WEB-L07](#web-l07) | Server reflects any Origin and allows credentials (CORS) | high |
| [WEB-L08](#web-l08) | Cookies are missing security flags | low |
| [WEB-L09](#web-l09) | Source maps are publicly reachable | medium |
| [WEB-L10](#web-l10) | Sensitive file is publicly readable | high |
| [WEB-L11](#web-l11) | Server shows detailed error pages | medium |

### WEB-001

**Production source maps are enabled** — low · CWE-540 · OWASP A05 · modes: static

The build config publishes source maps in production, letting anyone download and read your original source code, comments and internal routes.

**Fix:** Disable production source maps (productionSourceMap false, build.sourcemap false) or upload them privately to your error tracker.

### WEB-002

**CORS allows any origin to make credentialed requests** — high · CWE-942 · OWASP A05 · modes: static

The CORS configuration reflects or allows every origin together with credentials, so any website a logged-in user visits can read authenticated responses from your API.

**Fix:** Replace the wildcard or reflected origin with an explicit allow-list of trusted origins.

### WEB-003

**Unsanitized value written into the page** — high · CWE-79 · OWASP A03 · modes: static

A value is written into the DOM with an HTML sink such as dangerouslySetInnerHTML or innerHTML without sanitization, so attacker-controlled content can run script in your users' browsers (XSS).

**Fix:** Render text instead of HTML, or sanitize with a vetted library such as DOMPurify before using an HTML sink.

### WEB-004

**Next.js app does not configure security headers** — low · CWE-693 · OWASP A05 · modes: static

The Next.js project sets no security headers (CSP, frame protection, nosniff, referrer policy), leaving browsers' built-in defenses switched off.

**Fix:** Add a headers() block in next.config or middleware that sets Content-Security-Policy, X-Content-Type-Options, frame-ancestors and Referrer-Policy.

### WEB-006

**File write uses an attacker-controlled name with no sanitization** — high · CWE-22 · OWASP A01 · modes: static

A file write builds its path from a name the client controls, such as an uploaded file's name, without stripping traversal segments. An attacker can write outside the intended folder and overwrite code or config.

**Fix:** Generate the stored file name yourself or reduce the input with path.basename, and verify the resolved path stays inside the upload directory.

### WEB-007

**Next.js image optimizer accepts images from any host** — medium · CWE-918 · OWASP A05 · modes: static

images.remotePatterns (or domains) allows every hostname, so /_next/image fetches and re-serves any URL an attacker supplies: a free image proxy on your bill, content laundering under your domain, and a way to probe internal addresses.

**Fix:** List the exact hostnames and path prefixes your app loads images from.

### WEB-008

**Next.js image optimizer serves SVG without a sandbox** — medium · CWE-79 · OWASP A03 · modes: static

dangerouslyAllowSVG is enabled without a sandboxing contentSecurityPolicy and contentDispositionType 'attachment', so an SVG opened directly can run script on your origin.

**Fix:** Add contentDispositionType: 'attachment' and a CSP with sandbox next to dangerouslyAllowSVG, or drop it.

### WEB-009

**Message listener does not check the sender's origin** — medium · CWE-346 · OWASP A01 · modes: static

A window 'message' handler uses event.data without comparing event.origin to your own origin or an allowlist, so any page that can open or frame your site can drive the handler with crafted messages.

**Fix:** Check event.origin against an exact allowlist before using event.data, and validate the message shape.

### WEB-010

**Token or session data sent with postMessage to any origin** — high · CWE-201 · OWASP A02 · modes: static

postMessage is called with targetOrigin '*' and a payload containing a token, session or auth value, so whichever page occupies the target window receives the credential.

**Fix:** Pass the exact receiving origin instead of '*'.

### WEB-011

**Error details returned to clients** — medium · CWE-209 · OWASP A05 · modes: static

A request handler returns the caught error (message, stack or the whole object) in the HTTP response, leaking file paths, SQL and SDK internals to attackers. Stack traces are rated high.

**Fix:** Log the error on the server and return a generic message; expose only messages from your own safe error classes.

### WEB-L01

**Content-Security-Policy header missing or weak** — medium · CWE-693 · OWASP A05 · modes: live

The live site sends no Content-Security-Policy, or one that allows unsafe-inline, unsafe-eval or wildcard script sources, so one injected script becomes account takeover.

**Fix:** Send a CSP with a restrictive script-src (nonces or hashes) and no unsafe-inline, unsafe-eval or wildcard sources.

### WEB-L02

**Strict-Transport-Security header missing or too short** — low · CWE-319 · OWASP A02 · modes: live

The site does not send HSTS, or its max-age is short, so browsers may first connect over plain HTTP where a network attacker can downgrade or intercept the session.

**Fix:** Send Strict-Transport-Security with a long max-age (at least 180 days), ideally with includeSubDomains.

### WEB-L03

**Clickjacking protection missing** — low · CWE-1021 · OWASP A05 · modes: live

The site sends neither X-Frame-Options nor a CSP frame-ancestors directive, so another site can embed it in an invisible frame and trick users into clicking.

**Fix:** Send X-Frame-Options: DENY (or SAMEORIGIN) or a CSP frame-ancestors directive.

### WEB-L04

**X-Content-Type-Options header missing** — low · CWE-693 · OWASP A05 · modes: live

Without X-Content-Type-Options: nosniff, browsers may guess file types and execute uploaded content as script.

**Fix:** Send X-Content-Type-Options: nosniff on all responses.

### WEB-L05

**Referrer-Policy header missing** — low · CWE-200 · OWASP A05 · modes: live

Without a Referrer-Policy, full URLs (which can contain tokens or ids) may leak to other sites through the Referer header.

**Fix:** Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).

### WEB-L06

**Permissions-Policy header missing** — low · CWE-693 · OWASP A05 · modes: live

Without a Permissions-Policy, embedded or injected content may request powerful browser features such as camera, microphone or location.

**Fix:** Send a Permissions-Policy that disables the features your site does not use.

### WEB-L07

**Server reflects any Origin and allows credentials (CORS)** — high · CWE-942 · OWASP A05 · modes: live

The live server echoes an attacker-chosen Origin in Access-Control-Allow-Origin and also allows credentials, so any website can make authenticated requests as the visitor and read the responses.

**Fix:** Validate the Origin against an explicit allow-list instead of reflecting it, and never combine a reflected origin with credentials.

### WEB-L08

**Cookies are missing security flags** — low · CWE-614 · OWASP A05 · modes: live

Some cookies are set without Secure, HttpOnly or SameSite. Without HttpOnly an injected script can steal them; without Secure they travel over plain HTTP. Severity rises to medium for session-like cookies.

**Fix:** Set Secure, HttpOnly and SameSite=Lax (or Strict) on every cookie, especially session cookies.

### WEB-L09

**Source maps are publicly reachable** — medium · CWE-540 · OWASP A05 · modes: live

The site's JavaScript points to .map files anyone can download, and they contain the original source code.

**Fix:** Stop publishing source maps in production or serve them only to authenticated tooling.

### WEB-L10

**Sensitive file is publicly readable** — high · CWE-538 · OWASP A05 · modes: live

A well-known sensitive path (.env, .git, wp-config backup, .DS_Store, phpinfo) returns the real file's contents. Severity is critical when secrets are present and medium for low-impact files.

**Fix:** Remove the file from the web root, block the path in your server config, and rotate any secrets it contained.

### WEB-L11

**Server shows detailed error pages** — medium · CWE-209 · OWASP A05 · modes: live

Requesting a nonexistent path returns a stack trace or framework debug page, revealing file paths, versions and internals to attackers.

**Fix:** Disable debug mode in production and return a generic error page.

## SupplyChain

| Id | Title | Severity |
| --- | --- | --- |
| [SUP-000](#sup-000) | package.json could not be parsed | info |
| [SUP-001](#sup-001) | Dependency name looks like a typosquat of a popular package | high |
| [SUP-002](#sup-002) | Dependency name looks like an AI-hallucinated package | medium |
| [SUP-003](#sup-003) | Lifecycle script downloads or evaluates remote code | high |
| [SUP-004](#sup-004) | Known compromised package release | critical |
| [SUP-005](#sup-005) | Dependency is not installed from a pinned registry version | medium |
| [SUP-006](#sup-006) | Dependencies declared without a lockfile | low |
| [SUP-008](#sup-008) | Auth token committed in .npmrc | critical |
| [SUP-009](#sup-009) | Locked dependencies run install scripts | low |
| [SUP-010](#sup-010) | Framework version with a known critical or high advisory | critical |
| [SUP-011](#sup-011) | Dependency tracks an unstable dist-tag | medium |
| [SUP-012](#sup-012) | overrides/resolutions point at a git, tarball or URL source | medium |
| [SUP-013](#sup-013) | Package manager config weakens registry security | medium |
| [SUP-014](#sup-014) | pull_request_target workflow checks out untrusted PR code | critical |
| [SUP-015](#sup-015) | Untrusted event data interpolated into a workflow script | high |
| [SUP-016](#sup-016) | Workflow grants permissions: write-all | medium |
| [SUP-017](#sup-017) | Third-party action pinned to a branch | low |
| [SUP-018](#sup-018) | Hidden Unicode in AI agent instructions | high |
| [SUP-019](#sup-019) | MCP server launched from an unpinned package | medium |
| [SUP-020](#sup-020) | Literal credential in MCP server env | medium |

### SUP-000

**package.json could not be parsed** — info · modes: static

A package.json is not valid JSON, so its dependencies were not checked. npm itself would also refuse to install from it.

**Fix:** Fix the JSON syntax error without changing dependency versions, then re-run the scan.

### SUP-001

**Dependency name looks like a typosquat of a popular package** — high · CWE-1357 · OWASP A06 · modes: static

A dependency is one typo, a look-alike character or a scope mix-up away from a popular package. Attackers register such names and wait for a mistyped or AI-suggested install; the package's install scripts then run on your machine and CI.

**Fix:** Check the spelling, install the intended package, uninstall the look-alike, and install with --ignore-scripts until verified.

### SUP-002

**Dependency name looks like an AI-hallucinated package** — medium · CWE-1357 · OWASP A06 · modes: static

The name follows patterns AI assistants invent (popular name plus -utils, -helpers, ...) and the lockfile has no verified registry entry for it. Attackers register hallucinated names (slopsquatting), so the package may be malware. This is a heuristic.

**Fix:** Confirm the package exists, is maintained and is what you meant (npm view); otherwise remove it and write the code yourself or use the real package.

### SUP-003

**Lifecycle script downloads or evaluates remote code** — high · CWE-829 · OWASP A08 · modes: static

One of the project's own lifecycle scripts (preinstall, install, postinstall, prepare, prepublishOnly, postpack, ...) fetches, decodes or evaluates remote code with curl, wget, node -e, eval, atob, base64 piped to a shell, or npx pkg@latest. Whoever controls the source controls every machine that installs or publishes the package.

**Fix:** Remove the remote download; vendor the file or add a pinned dependency, and install with npm ci --ignore-scripts.

### SUP-004

**Known compromised package release** — critical · CWE-506 · OWASP A08 · modes: static

An exactly pinned or lockfile-resolved dependency is a release that was publicly reported as malicious or sabotaged. Secrets reachable where it was installed (npm tokens, cloud keys, .env files) should be treated as exposed.

**Fix:** Move to a clean version, delete node_modules and the lockfile entry, check npm ls for other copies, and rotate secrets present where it ran.

### SUP-005

**Dependency is not installed from a pinned registry version** — medium · CWE-829 · OWASP A08 · modes: static

A dependency uses a wildcard, git branch, remote tarball, unpinned GitHub shorthand or a file path outside the repository. The code behind it can change without a version bump and bypasses registry integrity checks.

**Fix:** Use an exact registry version, or pin git dependencies to a full commit hash.

### SUP-006

**Dependencies declared without a lockfile** — low · CWE-1357 · OWASP A06 · modes: static

No package-lock.json, pnpm-lock.yaml, yarn.lock or bun lockfile exists. Every install resolves the newest matching versions, so a malicious release published tomorrow lands in your next deploy and nothing records integrity hashes.

**Fix:** Generate and commit a lockfile and install from it with npm ci --ignore-scripts.

### SUP-008

**Auth token committed in .npmrc** — critical · CWE-798 · modes: static

A registry auth token is stored in a committed .npmrc. Anyone who can read the repository, its history or build logs can publish as you or read private packages.

**Fix:** Revoke the token, replace the value with an environment variable (_authToken=${NPM_TOKEN}) and purge it from git history.

### SUP-009

**Locked dependencies run install scripts** — low · CWE-829 · OWASP A08 · modes: static

Packages in the lockfile declare install scripts that execute during npm install. Most are legitimate native builds, but install scripts are how most npm malware runs, before the package is ever imported. Informational.

**Fix:** Install with scripts disabled (npm ci --ignore-scripts, ignore-scripts=true) and rebuild only packages that need it.

### SUP-010

**Framework version with a known critical or high advisory** — critical · CWE-1395 · OWASP A06 · modes: static

The resolved (lockfile) or exactly pinned version of Next.js or a react-server-dom package lies inside the affected range of a GitHub security advisory, for example the middleware authorization bypass CVE-2025-29927 or the React Server Components remote code execution CVE-2025-55182. Severity follows the advisory and is raised or lowered by what the repo shows (middleware that performs auth, an app/ directory).

**Fix:** Upgrade to the first patched version named in the finding (npm install next@<fixed>), regenerate the lockfile and redeploy.

### SUP-011

**Dependency tracks an unstable dist-tag** — medium · CWE-1357 · OWASP A06 · modes: static

A dependency spec is a moving tag such as canary, beta, next, rc, alpha or experimental. It installs unreviewed builds that change without a version bump, which is also what a hijacked publish token ships first.

**Fix:** Pin a released version exactly and commit the lockfile.

### SUP-012

**overrides/resolutions point at a git, tarball or URL source** — medium · CWE-829 · OWASP A08 · modes: static

overrides, resolutions or pnpm.overrides replace a package everywhere in the tree with code from a git repository or remote tarball. That bypasses registry integrity checks and silently affects transitive dependencies; pinned commits are lower risk than branches or URLs.

**Fix:** Reference a published registry version or a vendored file: path instead.

### SUP-013

**Package manager config weakens registry security** — medium · CWE-829 · OWASP A08 · modes: static

A .npmrc, .yarnrc.yml or .yarnrc uses an http registry, disables TLS verification (strict-ssl=false, enableStrictSsl: false) or combines always-auth with a hardcoded token. Network attackers can then substitute packages.

**Fix:** Use https registry URLs, keep certificate checks on, and read tokens from environment variables.

### SUP-014

**pull_request_target workflow checks out untrusted PR code** — critical · CWE-94 · OWASP A08 · modes: static

A workflow triggered by pull_request_target (secrets and write token) checks out the pull request head or fork and then builds it. Anyone who can open a pull request can run code with your secrets (a pwn request).

**Fix:** Use the pull_request trigger for builds, or never check out or execute PR code in the privileged workflow.

### SUP-015

**Untrusted event data interpolated into a workflow script** — high · CWE-94 · OWASP A08 · modes: static

A run: or github-script block expands ${{ github.event... }} fields an outsider controls (titles, bodies, branch names, commit messages) straight into the script, which allows shell and script injection with the job's secrets.

**Fix:** Pass the value through env: and use it as a quoted shell variable ("$TITLE").

### SUP-016

**Workflow grants permissions: write-all** — medium · CWE-1357 · OWASP A06 · modes: static

write-all gives the job token every write scope, so any compromised step or dependency in the job can push code, alter releases or publish packages.

**Fix:** Declare permissions: contents: read at the top and grant extra scopes per job only where needed.

### SUP-017

**Third-party action pinned to a branch** — low · CWE-829 · OWASP A08 · modes: static

A non-GitHub action is referenced by a branch such as @main or @master. Its owner, or anyone who compromises the account, can change what runs in your pipeline without any change in your repository.

**Fix:** Pin the action to a full commit SHA, noting the version in a comment.

### SUP-018

**Hidden Unicode in AI agent instructions** — high · CWE-94 · OWASP A08 · modes: static

A rules or MCP config file (.cursorrules, CLAUDE.md, AGENTS.md, copilot instructions, .mcp.json, ...) contains zero-width, bidirectional-control or Unicode tag characters. Reviewers cannot see them but coding agents read them, so they can carry hidden instructions (the rules file backdoor).

**Fix:** Remove the invisible characters, rewrite the file, and review its history for who introduced them.

### SUP-019

**MCP server launched from an unpinned package** — medium · CWE-829 · OWASP A08 · modes: static

An MCP server is started with npx, bunx, uvx or pnpm dlx without a pinned version, so each launch downloads and runs the newest published code with the agent's environment and file access.

**Fix:** Pin an exact package version in args after verifying the package and publisher.

### SUP-020

**Literal credential in MCP server env** — medium · CWE-798 · OWASP A08 · modes: static

An MCP config sets a *_TOKEN, *_KEY, *_SECRET or *_PASSWORD env var to a literal value that is not a recognised provider token. MCP configs are usually committed or synced, so the value spreads to every clone.

**Fix:** Rotate the credential and reference an environment variable instead of the value.

## AIGuard

| Id | Title | Severity |
| --- | --- | --- |
| [AI-001](#ai-001) | LLM provider called from browser code | critical |
| [AI-002](#ai-002) | User input flows into the system prompt | high |
| [AI-003](#ai-003) | LLM output used in a dangerous sink | high |
| [AI-004](#ai-004) | LLM endpoint has no authentication or rate limiting | high |
| [AI-005](#ai-005) | LLM call has no output cap or input length limit | medium |
| [AI-006](#ai-006) | Untrusted content pasted into a tool-enabled prompt | medium |
| [AI-007](#ai-007) | Model API key exposed through a public env var | high |
| [AI-008](#ai-008) | MCP tool passes model-chosen arguments to a dangerous sink | high |
| [AI-009](#ai-009) | Vector search is not scoped to the current user or tenant | medium |
| [AI-010](#ai-010) | Agent loop has no step cap | low |

### AI-001

**LLM provider called from browser code** — critical · CWE-798 · OWASP LLM10 · modes: static

A model provider SDK or API is called from code that ships to the browser, so the API key is visible to every visitor who can then spend your credits or abuse your account.

**Fix:** Move the call behind your own authenticated, rate-limited server route and keep the provider key in a server-only environment variable.

### AI-002

**User input flows into the system prompt** — high · CWE-77 · OWASP LLM01 · modes: static

Request-controlled text is concatenated into a system or developer prompt. An attacker can rewrite the model's instructions (prompt injection), leak the prompt or steer tool use.

**Fix:** Keep system prompts static, pass user text only as a user message, and validate or delimit anything untrusted.

### AI-003

**LLM output used in a dangerous sink** — high · CWE-94 · OWASP LLM05 · modes: static

Model output reaches eval, a shell, a SQL query, dynamic import, tool dispatch or raw HTML. Because output can be steered by prompt injection, this becomes code execution, SQL injection or XSS.

**Fix:** Treat model output as untrusted input: validate against a schema, use allow-lists for tools and commands, parameterize queries and escape or sanitize markup.

### AI-004

**LLM endpoint has no authentication or rate limiting** — high · CWE-306 · OWASP LLM10 · modes: static

A public route or action spends model credits with neither authentication nor rate limiting, so anyone can run up your bill or abuse the model through your key.

**Fix:** Require a session, add per-user rate limits and a spending cap on the route that calls the model.

### AI-005

**LLM call has no output cap or input length limit** — medium · CWE-770 · OWASP LLM10 · modes: static

A model call has no max output tokens and the user-supplied text is not length-limited, so a single request can consume an unbounded amount of tokens and money.

**Fix:** Set max_tokens (or the provider equivalent) and reject or truncate oversized user input before calling the model.

### AI-006

**Untrusted content pasted into a tool-enabled prompt** — medium · CWE-77 · OWASP LLM01 · modes: static

Fetched, retrieved or stored content is pasted undelimited into the prompt of a call that has tools. A hostile document can carry instructions (indirect prompt injection) that make the model invoke those tools.

**Fix:** Delimit untrusted content clearly, strip instructions where possible, and restrict the tools and permissions available to calls that read it.

### AI-007

**Model API key exposed through a public env var** — high · CWE-798 · OWASP LLM02 · modes: static

A model provider key is read through a public environment prefix (NEXT_PUBLIC_, VITE_, REACT_APP_). Public variables are inlined into the browser bundle, so the key is exposed (critical when read from client code).

**Fix:** Rename the variable without the public prefix, read it only on the server, and rotate the exposed key.

### AI-008

**MCP tool passes model-chosen arguments to a dangerous sink** — high · CWE-78 · OWASP LLM06 · modes: static

An MCP server tool handler uses its arguments as a shell command (critical), outgoing URL, file path or SQL string with no allowlist. The arguments are written by a model that reads untrusted text, so a poisoned document can drive the tool into command execution, SSRF, file access or SQL injection.

**Fix:** Validate tool arguments with enums and allowlists, use execFile with an argument array, confine file paths to one directory, and use parameterised queries.

### AI-009

**Vector search is not scoped to the current user or tenant** — medium · CWE-639 · OWASP LLM08 · modes: static

A similarity search (Pinecone query, Supabase match_* RPC or pgvector SQL) has no user or tenant filter in an app with signed-in users, so one customer's query can retrieve another customer's private documents. Reported with low confidence because some indexes are intentionally shared.

**Fix:** Use a per-user namespace or a metadata filter / WHERE predicate built from the verified session user id.

### AI-010

**Agent loop has no step cap** — low · CWE-835 · OWASP LLM10 · modes: static

A tool-using model call runs in a while(true) or recursive loop with no iteration counter, or with maxSteps / stepCountIs above 20, so a looping or hijacked agent can burn unbounded credits and hammer the tools' backends.

**Fix:** Cap steps (stopWhen: stepCountIs(n) with a small n, or a MAX_STEPS counter) and stop on the first final answer.

## InjectionHunter

| Id | Title | Severity |
| --- | --- | --- |
| [INJ-001](#inj-001) | SQL query is built from request data | critical |
| [INJ-002](#inj-002) | Prisma unsafe raw query takes a non-literal query string | high |
| [INJ-003](#inj-003) | Request data is placed inside a Supabase (PostgREST) filter string | medium |
| [INJ-004](#inj-004) | Shell command is built from request data | critical |
| [INJ-005](#inj-005) | Server fetches a URL chosen by the request (SSRF) | high |
| [INJ-006](#inj-006) | Redirect target comes from the request (open redirect) | medium |
| [INJ-007](#inj-007) | File path is built from request data (path traversal) | high |
| [INJ-008](#inj-008) | MongoDB filter uses a request value without forcing it to a string (operator injection) | high |
| [INJ-009](#inj-009) | Request data is executed as code | critical |
| [INJ-010](#inj-010) | Dynamic code execution with a non-literal string | medium |

### INJ-001

**SQL query is built from request data** — critical · CWE-89 · OWASP A03 · modes: static

Request data (body, query string, route params, form fields) is interpolated or concatenated into the SQL text given to pg, mysql2, sqlite, sequelize, typeorm, knex raw helpers, sql.raw or Prisma $queryRawUnsafe. An attacker can append their own SQL and read or change any table the database user can reach. Tagged templates, bound parameters, numeric coercion and allowlisted columns are recognised as safe.

**Fix:** Keep the SQL text constant and pass request values as bound parameters ($1 / ? placeholders, a values array, or prisma.$queryRaw tagged templates). Map sort/column names from a fixed object.

### INJ-002

**Prisma unsafe raw query takes a non-literal query string** — high · CWE-89 · OWASP A03 · modes: static

$queryRawUnsafe / $executeRawUnsafe run an assembled string with no escaping. No request data was seen reaching it, but a runtime-built query is one edit away from SQL injection, so it is flagged for review (medium confidence).

**Fix:** Use the parameterized tagged-template form prisma.$queryRaw`...`, or a literal string with $1.. placeholders and the values passed as extra arguments.

### INJ-003

**Request data is placed inside a Supabase (PostgREST) filter string** — medium · CWE-943 · OWASP A03 · modes: static

supabase-js .or(), .filter() and .textSearch() take a string in PostgREST syntax. When request data is interpolated into it, a visitor can add commas and operators to inject extra conditions and widen the query beyond what the page intended.

**Fix:** Use the typed helpers (.ilike, .eq, .in) or strip , ( ) " and backslashes from the value before building the filter string.

### INJ-004

**Shell command is built from request data** — critical · CWE-78 · OWASP A03 · modes: static

Request data reaches exec/execSync, or spawn/execa with shell: true or sh -c. Shell metacharacters in the value let an attacker run arbitrary commands on the server. execFile/spawn with an argument array and no shell are not flagged.

**Fix:** Use execFile or spawn with a fixed program and an argument array (no shell), and validate the value against an allowlist or a strict regex.

### INJ-005

**Server fetches a URL chosen by the request (SSRF)** — high · CWE-918 · OWASP A10 · modes: static

fetch, axios, got, ky, undici or http.get is called with a URL whose host (or the whole URL) comes from the request. The attacker can make the server call internal services and cloud metadata endpoints. A fixed origin with request data only in the path or query is not flagged.

**Fix:** Allowlist hosts (parse with new URL, require https, check hostname against a set) or build the URL from a fixed origin plus an encoded id.

### INJ-006

**Redirect target comes from the request (open redirect)** — medium · CWE-601 · OWASP A01 · modes: static

redirect(), NextResponse.redirect, res.redirect, router.push or window.location is given a value from next / redirect / returnTo / callbackUrl style parameters. Phishing links on your own domain can bounce users to an attacker's site, including through the ${origin}${next} callback pattern (next=@evil.com).

**Fix:** Allow only same-site relative paths (start with a single /, no //, backslash or @) or an allowlist of hosts, and fall back to a fixed page.

### INJ-007

**File path is built from request data (path traversal)** — high · CWE-22 · OWASP A01 · modes: static

readFile, createReadStream, sendFile, download, readdir, stat, writeFile, unlink or rm receives a path derived from the request. ../ sequences escape the intended folder, exposing secrets and source or, for unlink/rm, deleting files (critical). path.basename, a resolve + startsWith check and sendFile root are recognised as guards.

**Fix:** Reduce the value to a file name with path.basename, resolve it against a fixed base directory and reject paths that do not start with that base.

### INJ-008

**MongoDB filter uses a request value without forcing it to a string (operator injection)** — high · CWE-943 · OWASP A03 · modes: static

A mongoose/mongodb find, update or delete filter uses a request value directly. A JSON body such as {"$ne": null} is an operator, not text, and matches every document, enabling authentication bypass and cross-user data access.

**Fix:** Validate the body with a schema (zod: strings only), wrap values in String(), use $eq, or enable mongoose sanitizeFilter / express-mongo-sanitize.

### INJ-009

**Request data is executed as code** — critical · CWE-95 · OWASP A03 · modes: static

eval, new Function or vm.run* is given text derived from the request. This is remote code execution: the attacker runs JavaScript with the server's privileges and secrets.

**Fix:** Never execute request text. Parse it as data (JSON.parse, a schema, an expression library) or look the operation up in a fixed table of functions.

### INJ-010

**Dynamic code execution with a non-literal string** — medium · CWE-95 · OWASP A03 · modes: static

eval, new Function or vm.run* executes a string built at runtime. No request data was traced into it, but any future path from user text to this call is remote code execution, so it is flagged for review (medium confidence).

**Fix:** Replace dynamic execution with data parsing or a lookup of allowed functions.

## PyGuard

| Id | Title | Severity |
| --- | --- | --- |
| [PY-001](#py-001) | Flask debug mode enabled | high |
| [PY-002](#py-002) | Django DEBUG = True or ALLOWED_HOSTS wildcard | high |
| [PY-003](#py-003) | Hardcoded framework secret key | high |
| [PY-004](#py-004) | CSRF protection or secure cookies disabled | medium |
| [PY-005](#py-005) | CORS allows any origin with credentials | high |
| [PY-006](#py-006) | SQL built from strings (SQL injection) | high |
| [PY-007](#py-007) | OS command built from strings (command injection) | high |
| [PY-008](#py-008) | Unsafe deserialization | high |
| [PY-009](#py-009) | eval/exec on dynamic input | medium |
| [PY-010](#py-010) | Server-side request forgery from user-controlled URL | high |
| [PY-011](#py-011) | Path traversal from user-controlled file path | high |
| [PY-012](#py-012) | Data-touching route without authentication | high |
| [PY-013](#py-013) | Mass assignment from request body | medium |
| [PY-014](#py-014) | JWT verification disabled or hardcoded secret | high |
| [PY-015](#py-015) | Passwords hashed with a fast hash | high |

### PY-001

**Flask debug mode enabled** — high · CWE-489 · OWASP A05 · modes: static

Flask is started with debug=True (or FLASK_DEBUG=1 / app.debug = True). The Werkzeug debugger serves an interactive Python console in the browser; anyone who can reach the app and get an error page can run code on the server.

**Fix:** Never hardcode debug. Read it from the environment (default off) and run production under gunicorn/uwsgi instead of app.run().

### PY-002

**Django DEBUG = True or ALLOWED_HOSTS wildcard** — high · CWE-489 · OWASP A05 · modes: static

A Django settings file sets DEBUG = True unconditionally (or ALLOWED_HOSTS = ['*']). Debug pages leak settings, SQL, file paths and environment values; a wildcard host list enables Host-header poisoning such as password-reset link hijacking.

**Fix:** Drive DEBUG from an environment variable that defaults to False and list real hostnames in ALLOWED_HOSTS.

### PY-003

**Hardcoded framework secret key** — high · CWE-798 · OWASP A02 · modes: static

Flask's secret_key / SECRET_KEY or Django's SECRET_KEY is a string literal in source. Whoever can read the repository can forge session cookies, signed tokens and password-reset links, which is full account takeover.

**Fix:** Load the key from an environment variable or secret manager, fail startup if it is missing, and rotate the exposed key.

### PY-004

**CSRF protection or secure cookies disabled** — medium · CWE-352 · OWASP A01 · modes: static

CSRF protection is switched off (@csrf_exempt on a state-changing view, WTF_CSRF_ENABLED = False) or session/CSRF cookies are allowed over plain HTTP. A malicious page can make a logged-in user's browser perform actions or leak cookies.

**Fix:** Remove the exemption and send the CSRF token with each request; set *_COOKIE_SECURE = True outside local development.

### PY-005

**CORS allows any origin with credentials** — high · CWE-942 · OWASP A05 · modes: static

CORS is configured with a wildcard (or default) origin together with credentials. Any website a user visits can then call the API as that user and read the responses.

**Fix:** List the exact front-end origins in allow_origins / origins instead of '*'.

### PY-006

**SQL built from strings (SQL injection)** — high · CWE-89 · OWASP A03 · modes: static

A SQL statement is assembled with an f-string, %, + or .format() and passed to execute()/text()/raw()/extra(). An attacker who controls any interpolated value can read, modify or delete the whole database. Critical when the value comes straight from request input.

**Fix:** Pass values as bound parameters (execute('... %s', (x,)) or text('... :x') with a dict) and never format them into the SQL text.

### PY-007

**OS command built from strings (command injection)** — high · CWE-78 · OWASP A03 · modes: static

A shell command is built from non-literal data and run with shell=True, os.system or os.popen. Shell metacharacters in the data (; | $()) run arbitrary commands as the server user. Critical when the data comes from request input.

**Fix:** Pass an argument list without shell=True (subprocess.run(['cmd', arg], check=True)) and validate arg against an allowlist.

### PY-008

**Unsafe deserialization** — high · CWE-502 · OWASP A08 · modes: static

pickle/dill/marshal loads attacker-influenced bytes, or yaml.load is used without a safe loader. Crafted input executes arbitrary code during deserialization.

**Fix:** Use JSON for untrusted data, and yaml.safe_load instead of yaml.load. Never unpickle data from users or uploads.

### PY-009

**eval/exec on dynamic input** — medium · CWE-95 · OWASP A03 · modes: static

eval() or exec() runs a non-literal string. If any part of it comes from a request, a user runs arbitrary Python on your server (critical); otherwise it is a fragile pattern that invites that bug later.

**Fix:** Use ast.literal_eval for data, json.loads for JSON, and an explicit dispatch table for operations.

### PY-010

**Server-side request forgery from user-controlled URL** — high · CWE-918 · OWASP A10 · modes: static

requests/httpx/urllib fetches a URL taken from request input with no host allowlist. Attackers point it at cloud metadata (169.254.169.254) or internal services and read credentials or private data through your server.

**Fix:** Parse the URL, require https, and check the hostname against an explicit allowlist before fetching.

### PY-011

**Path traversal from user-controlled file path** — high · CWE-22 · OWASP A01 · modes: static

open()/send_file()/FileResponse()/send_from_directory() receives a path built from request input without sanitising it. ../../ sequences let attackers read any file the server can, such as .env, SSH keys or source code.

**Fix:** Use secure_filename or os.path.basename, resolve the final path and confirm it stays inside the intended directory.

### PY-012

**Data-touching route without authentication** — high · CWE-306 · OWASP A01 · modes: static

A FastAPI or Flask route reads or writes the database but has no auth dependency/decorator. Anyone on the internet can call it and read or change other users' data. Reported at medium confidence because auth may be enforced by middleware this scanner cannot see.

**Fix:** Add Depends(get_current_user) (FastAPI) or @login_required/@jwt_required (Flask) and filter data by the authenticated user.

### PY-013

**Mass assignment from request body** — medium · CWE-915 · OWASP A04 · modes: static

A request body is splatted straight into a model (Model(**request.json), **payload.dict()) or a DRF serializer exposes fields = '__all__'. Users can set fields they should not, such as is_admin, role or owner_id.

**Fix:** Declare an explicit allowlist of writable fields (a Pydantic input schema or serializer fields tuple).

### PY-014

**JWT verification disabled or hardcoded secret** — high · CWE-347 · OWASP A02 · modes: static

jwt.decode runs with verify_signature False or algorithms ['none'], or tokens are signed with a literal secret. Attackers can mint tokens for any user (critical when verification is off).

**Fix:** Always verify with a fixed algorithm list (['HS256'] or ['RS256']) and a secret from the environment.

### PY-015

**Passwords hashed with a fast hash** — high · CWE-916 · OWASP A02 · modes: static

A password is hashed with hashlib md5/sha1/sha256. These hashes are built for speed, so a leaked database is cracked at billions of guesses per second.

**Fix:** Use a slow password hash such as argon2-cffi, bcrypt, or werkzeug.security.generate_password_hash / django.contrib.auth.hashers.make_password.

## AI review (opt-in, whsquad review)

| Id | Title | Severity |
| --- | --- | --- |
| [REV-001](#rev-001) | Broken object-level authorization (IDOR / cross-tenant access) | high |
| [REV-002](#rev-002) | Missing function-level authorization (role or plan check) | high |
| [REV-003](#rev-003) | Business logic can be abused (price, quantity, coupon or state) | high |
| [REV-004](#rev-004) | Race condition or double-spend on a check-then-act path | medium |
| [REV-005](#rev-005) | Server trusts identity or privileged fields sent by the client | high |
| [REV-006](#rev-006) | Request data reaches a dangerous sink through a helper | high |
| [REV-007](#rev-007) | Webhook, callback or redirect is trusted without verification | high |
| [REV-008](#rev-008) | AI feature can be steered into a privileged action | high |
| [REV-009](#rev-009) | Other trust-boundary violation found by AI review | medium |

### REV-001

**Broken object-level authorization (IDOR / cross-tenant access)** — high · CWE-639 · OWASP A01 · modes: static

AI review traced a request that reads or changes another user's or tenant's record because the id comes from the caller and no ownership or tenant check applies on that path, including checks that exist in some handlers but not this one.

**Fix:** Derive the owner or tenant from the session and filter by it (or enforce it in RLS) on every path to the record.

### REV-002

**Missing function-level authorization (role or plan check)** — high · CWE-285 · OWASP A01 · modes: static

AI review found an action reserved for admins, owners or a paid plan that any signed-in (or anonymous) caller can trigger, often because the check exists only in the UI.

**Fix:** Check the caller's role or plan on the server at the top of the handler, from the session or database, never from the request.

### REV-003

**Business logic can be abused (price, quantity, coupon or state)** — high · CWE-840 · OWASP A04 · modes: static

AI review found a flow where client-controlled values decide money, limits or state transitions: amounts or prices from the request, reusable coupons, negative quantities, or steps that can be skipped.

**Fix:** Compute prices, limits and transitions on the server from trusted data and validate each state change against the current state.

### REV-004

**Race condition or double-spend on a check-then-act path** — medium · CWE-367 · OWASP A04 · modes: static

AI review found a balance, stock, quota or one-time token that is read, checked and written in separate steps, so concurrent requests can pass the check twice.

**Fix:** Make the check and the write one atomic operation (a conditional UPDATE, a transaction with row locks, or a unique constraint).

### REV-005

**Server trusts identity or privileged fields sent by the client** — high · CWE-602 · OWASP A01 · modes: static

AI review found a handler that takes userId, role, ownerId, isAdmin or similar from the request body, query or headers and acts on it instead of the authenticated session.

**Fix:** Ignore identity and privilege fields from the request; read them from the verified session and allow-list writable fields.

### REV-006

**Request data reaches a dangerous sink through a helper** — high · CWE-74 · OWASP A03 · modes: static

AI review followed request data across files into SQL, a shell, a URL fetch, a file path or HTML, where the helper in another module does no escaping or validation (single-file rules cannot see this).

**Fix:** Validate at the boundary and use the safe API at the sink (parameterised queries, execFile argument arrays, URL allow-lists, path containment, escaping).

### REV-007

**Webhook, callback or redirect is trusted without verification** — high · CWE-345 · OWASP A08 · modes: static

AI review found a webhook, OAuth/payment callback or return URL whose payload or parameters are acted on (grant access, mark paid) without verifying the signature, state or amount with the provider.

**Fix:** Verify the provider signature or state, then re-fetch the authoritative object from the provider before acting.

### REV-008

**AI feature can be steered into a privileged action** — high · CWE-1427 · OWASP LLM01 · modes: static

AI review found model output or user-controlled prompt content that drives tools, database writes, emails or other privileged actions without an allow-list or confirmation step.

**Fix:** Treat model output as untrusted input: allow-list actions and arguments, scope them to the caller, and require confirmation for side effects.

### REV-009

**Other trust-boundary violation found by AI review** — medium · CWE-693 · OWASP A04 · modes: static

AI review found a concrete boundary violation outside the classes above. It still names the attacker, the crossed control and the result.

**Fix:** Enforce the stated invariant at the last trusted decision point, then re-check with `whsquad review --recheck`.
