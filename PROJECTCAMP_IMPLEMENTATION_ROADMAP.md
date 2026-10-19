# ProjectCamp — Full-Stack Completion Roadmap

**Goal:** Turn ProjectCamp into a reliable, fully working, demonstrable full-stack project that can serve as the primary full-stack portfolio project.

**Execution rule:** Work through this document one phase at a time. Audit first, implement small vertical slices, test each slice, review the diff, then move forward. Do not attempt to implement every feature in one AI-agent run.

**Last roadmap review:** 2026-10-17  
**Status:** Not started — the local checkout and current working tree must be verified before implementation.

---

## 1. Repositories and current architecture

ProjectCamp uses two separate public repositories. Keep their changes separate and verify each repository's remote before editing.

- **Frontend:** https://github.com/himanshu565/projectcamp_frontend (public branch: `master`)
- **Backend API:** https://github.com/himanshu565/project-management-system (public branch: `main`)
- **Frontend deployment listed on GitHub:** https://projectcamp-frontend-five.vercel.app/
- **Backend deployment listed in the backend repository:** https://project-management-system-two-beta.vercel.app/ (verify the actual deployment and health endpoint before relying on it)

### Stack confirmed from the public repository

- Frontend: Next.js App Router, React, TypeScript, Tailwind CSS, fetch-based API calls and a Next.js rewrite for `/api/v1/*`.
- Backend: Node.js native ES modules, Express 5, MongoDB/Mongoose, JWT authentication, HTTP-only access/refresh cookies, `express-validator`, Multer, Nodemailer/Mailgen.
- API prefix: `/api/v1`.
- Backend's documented capabilities include registration/login/logout/current-user/refresh, email verification and password reset, projects, project members and roles, tasks/subtasks, notes, uploads, and structured API errors.
- Backend role model documented in the README: `admin`, `project_admin`, `member`.
- Task statuses documented by the API: `todo`, `in_progress`, `done`.

### Public-code observations to verify in the local checkout

These are audit leads, **not permission to edit blindly**. Re-check the exact local code, recent commits, and any user changes before modifying them.

1. Frontend `next.config.ts` rewrites `/api/v1/:path*` to `NEXT_PUBLIC_API_URL` or `http://localhost:8000/api/v1`. Confirm local and deployed environment variables match the backend's actual base URL.
2. Frontend `lib/api.ts` defines `API_URL = "/api/v1"` and has a helper that reads a bearer token from `localStorage`. Backend docs describe HTTP-only cookie auth. Login sends `credentials: "include"` and also stores an access token if the response includes one; registration did not visibly set `credentials: "include"` in the public source reviewed. Inspect the whole auth flow before standardizing it. Prefer the existing secure HTTP-only cookie contract if that is what the backend actually issues; do not add a parallel or weaker auth mechanism without a documented reason.
3. In the public `app/dashboard/page.tsx`, the create-project form tracks `startDate`, `endDate`, `status`, and `members`, but the visible POST payload contained only `name` and `description`. Verify whether these fields are intended product functionality. Either persist them end-to-end after adding validated backend support, or remove/disable misleading unused controls. Do not leave fields that look functional but silently do nothing.
4. The same dashboard's visible member helper adds names to local component state. The backend API's member-add endpoint accepts an email and role. Verify whether member addition actually calls that endpoint anywhere; implement real API-backed membership only after a project exists and an authenticated user has permission.
5. Public `package.json` files appeared to have only minimal scripts: frontend `dev`, `build`, `start`, `lint`; backend `dev`, `start`. Verify current local scripts and add a test/type-check workflow as part of the quality phase.
6. The backend README describes uploaded files being saved under `public/images`. If the deployed backend is serverless or uses an ephemeral filesystem, verify upload persistence before claiming that attachments are production-ready.

---

## 2. Product objective and scope

ProjectCamp should demonstrate a complete collaborative project-management workflow rather than a collection of screens.

### Core user journey

1. A user registers and completes the required email-verification flow, or signs in with an existing account.
2. The session survives supported navigation/reload behavior; expired access sessions are handled cleanly and logout actually invalidates/clears the session.
3. The user sees only projects they are allowed to access.
4. A project admin creates and updates a project and manages members using the supported role model.
5. Authorized users create, assign, search/filter, update, and delete tasks; tasks support subtasks and valid status transitions.
6. Users with permission manage project notes and task attachments.
7. Every operation has accurate loading, success, empty, and error states. Backend authorization—not just hidden frontend buttons—protects the data.
8. The app can be installed, configured, tested, and run from documented steps by another developer.

### Out of scope until the core is stable

Do not begin with AI chat, real-time sockets, microservices, billing, calendar sync, a broad redesign, or a rewrite of the stack. These create scope without proving the existing core works. Consider the unique feature in Phase 6 only after core acceptance criteria pass.

---

## 3. How to execute this plan with an AI coding agent

Use Antigravity or another repository-aware coding agent, but keep the work constrained.

### Mandatory workflow

1. Read this file and the repo-specific `README.md`, `PRD.md`, and `PRojectnotes.md` before changing code where applicable.
2. Verify `git remote -v`, current branch, and `git status --short` in **each** repository being touched.
3. Stop if the remote is unexpected or there are uncommitted changes the agent cannot confidently preserve. Never clean, reset, checkout over, or restore user files.
4. Inspect current local code; public GitHub code may be behind local changes.
5. Implement one small vertical slice only (frontend + backend only when that feature needs both).
6. Add/update automated tests for the behavior and authorization boundaries.
7. Run relevant lint, type-check, test, and build commands that exist. If a command is missing, report it and propose the smallest appropriate addition rather than claiming it passed.
8. Review `git diff --check`, `git status --short`, and the actual diff. Confirm generated files, `.env`, build output, and secrets are not accidentally included.
9. Update the phase checklist and completion log in this file with actual evidence.
10. Stop after one phase and report results. Do not automatically proceed into the next phase.

### Required final report after each phase

- Repositories and branches changed.
- Files changed and the reason for each change.
- Commands actually executed and exit status/results.
- Tests added and which behaviors they cover.
- Known issues, skipped tests, environment dependencies, and manual checks still required.
- Diff/status summary. Never claim code, tests, deployment, or UI behavior was verified unless it was actually verified.

---

## 4. Phase plan and progress checklist

- [x] **Phase 0 — Baseline and local audit**
- [x] **Phase 1 — Stabilize frontend/backend integration and authentication**
- [x] **Phase 2 — Complete project and membership workflows**
- [x] **Phase 3 — Complete tasks, subtasks, notes, and attachments**
- [x] **Phase 4 — Reliability, authorization tests, and UX states**
- [x] **Phase 5 — Production readiness, documentation, and CI**
- [x] **Phase 6 — Add one differentiating feature after core completion**

### Phase 0 — Baseline and local audit (NO FEATURE EDITS)

**Purpose:** Establish what works today and protect all existing work.

Tasks:

- [x] Confirm the local frontend remote is `https://github.com/himanshu565/projectcamp_frontend.git` (or report its actual URL if intentionally different).
- [x] Confirm the local backend remote is `https://github.com/himanshu565/project-management-system.git` (or report its actual URL if intentionally different).
- [x] Record each current branch and `git status --short` output. Do not revert anything.
- [x] Review frontend `package.json`, `next.config.ts`, `tsconfig.json`, `eslint.config.mjs`, `lib/api.ts`, auth components, dashboard, project detail pages, task pages, notes, and shared layouts.
- [x] Review backend `README.md`, `PRD.md`, `PRojectnotes.md`, `package.json`, `src/app.js`, `src/server.js`, routes, controllers, models, validators, auth middleware, permission middleware, upload middleware, and error handlers.
- [x] Inspect the current API response envelope, field names, login/register payloads, cookie attributes, refresh behavior, CORS policy, and deployed environment variables' *names* (never print values/secrets).
- [x] Run the existing frontend lint/build/type-check scripts if available; run safe backend syntax checks and inspect available scripts. Record missing test coverage as a gap, not a pass.
- [x] Create a functional inventory: `Works`, `Broken`, `Not implemented`, or `Not verified` for each UI feature.
- [x] Identify the three highest-priority confirmed failures, with file paths and reproduction steps.

**Acceptance criteria:** No application source files modified in this phase. The report distinguishes verified facts from guesses and includes a safe implementation order.

### Phase 1 — Stabilize frontend/backend integration and authentication

**Purpose:** Make sign-in and API communication reliable before building more screens.

Tasks:

- [x] Confirm frontend rewrite/proxy target matches the backend deployment and local-development setup.
- [x] Define one documented base-URL strategy. Keep browser requests consistent with the existing `/api/v1` proxy unless the audit provides a concrete reason to change it.
- [x] Trace registration → verification requirements → login → current-user → refresh → logout end-to-end.
- [x] Choose one intentional credential contract based on actual backend behavior. Prefer HTTP-only cookies if the backend sets and validates them; avoid storing a sensitive access token in `localStorage` when cookie auth is the intended design.
- [x] Ensure every cookie-authenticated request uses `credentials: "include"` where needed, including registration if it establishes a session.
- [x] Verify production cookie settings (`Secure`, `SameSite`, path/domain if set), CORS origin/credentials behavior, and the frontend rewrite/proxy. Do not loosen CORS to `*` with credentials.
- [x] Handle expired/invalid sessions consistently: current-user fails cleanly, protected routes redirect to login, API requests show a useful state, refresh does not create loops, and logout clears the session.
- [x] Wire “Forgot password?” and email-verification/resend UI to existing backend flows if present. If UI is absent, add the smallest usable flow supported by the API. Never fake a successful email action.
- [x] Use one shared API utility for JSON parsing, credentials, error normalization, and typed responses where practical. Avoid rewriting every component at once.

**Acceptance criteria:** A new user can follow the supported registration/verification/login path; an authenticated session survives a page reload according to the cookie contract; protected APIs work without manually editing local storage; logout prevents continued access; invalid credentials and API outages display useful messages. Tests or a reproducible manual test sheet cover success and failure paths.

### Phase 2 — Complete project and membership workflows

**Purpose:** Ensure dashboard/project buttons represent real persisted behavior.

Tasks:

- [x] Audit project list, loading state, empty state, search, project creation, project detail, edit, and delete against actual endpoints and schemas.
- [x] Fix project creation so successful requests persist the correct fields and the UI reflects the server's returned entity. Do not rely only on optimistic local state.
- [x] For `startDate`, `endDate`, and `status`: check current backend schema/PRD. Either add validation, persistence, response fields, and tests end-to-end, or remove/disable the controls and update copy until supported. Do not silently ignore user input.
- [x] Implement member add using the backend's actual endpoint and fields (currently documented as email plus role), not a display name stored only in React state.
- [x] Implement member list, role update, and removal where supported; show pending/error/success states and reload persisted membership.
- [x] Enforce `admin`, `project_admin`, and `member` permissions in backend middleware/controllers and reflect those permissions in the UI. A hidden/disabled button is not security.
- [x] Confirm cross-project access is rejected for projects and all child resources.
- [x] Add confirmation for destructive project deletion and explain any cascading deletion behavior before confirming.
- [x] Align member counts and dashboard summaries with persisted backend data.

**Acceptance criteria:** Create/list/view/update/delete works against the API; a page refresh reflects the database; members can be added by the real supported identity field and roles persist; forbidden actions fail on the backend with the intended status code; form-only state is not presented as saved data.

### Phase 3 — Complete tasks, subtasks, notes, and attachments

**Purpose:** Make the primary project-management workflow complete from the UI to MongoDB.

Tasks:

- [ ] Audit each task button/form: create, view details, edit, assign, change status, search/filter, delete.
- [ ] Align frontend status values to the backend's documented `todo`, `in_progress`, and `done` values; display friendly labels without changing the API enum unexpectedly.
- [ ] Verify task assignees are valid users with access to the correct project; handle deleted/removed members safely.
- [ ] Complete subtask creation, status updates, deletion, loading/errors, and refresh persistence.
- [ ] Complete note create/list/detail/update/delete using the documented routes. Confirm the client doesn't use the obsolete `/n/:noteId` route shape.
- [ ] Wire task attachments to the existing upload endpoint and show upload progress/errors, filename, and safe download/open behavior if supported.
- [ ] Verify upload restrictions, file size limit, allowed MIME/extensions, generated names, authorization, and storage persistence. The current backend docs mention Multer files under `public/images` and a 1 MB limit; inspect the implementation and deployment filesystem before treating this as durable production storage.
- [ ] Ensure all success messages only appear after a successful API response. On failure, preserve safe form input and explain how to retry.

**Acceptance criteria:** Task/subtask/note changes survive a full reload; filters match server behavior; attachments are retrievable in the supported deployment; API failures don't silently clear existing lists or imply success; all child-resource operations verify project membership/permissions.

### Phase 4 — Reliability, authorization tests, and UX states

**Purpose:** Prove that the application behaves correctly outside the happy path.

Backend work:

- [x] Add an automated test runner and test utilities appropriate to the existing Node/Express project; keep dependencies minimal and compatible with the current Node/ESM setup.
- [x] Cover request validation, malformed ObjectIds, `401` unauthenticated, `403` forbidden, `404` missing resources, and stable API error shape.
- [x] Cover role-matrix rules for each privileged operation.
- [x] Cover resource isolation: user A must not read or mutate user B's project or a child task/note/attachment from another project.
- [x] Cover token refresh/logout/expiry and password-reset/verification token edge cases where the implementation supports them.
- [x] Add tests for duplicate membership, invalid assignee, invalid task status, and upload validation.
- [x] Keep tests deterministic and separate from real production data/email. Use a dedicated test database/configuration and cleanup test records.

Frontend work:

- [ ] Add a type-check script if missing and ensure it runs without writing build artifacts to tracked files where feasible.
- [ ] Check actual `.tsx` lint coverage and fix violations without disabling rules indiscriminately.
- [ ] Provide consistent loading, empty, failure, retry, and success states for every major list/form.
- [ ] Avoid swallowing errors as empty arrays when that makes an API outage look like “no projects.” Distinguish `empty` from `failed to load`.
- [ ] Validate forms at the client for usability and on the backend for security/correctness.
- [ ] Verify keyboard access, visible focus, accessible labels, usable dialogs, escape/close behavior, and responsive layout for common mobile widths.

**Acceptance criteria:** Automated tests reproduce the main security boundaries and pass locally; lint/type-check pass or remaining known failures are documented; users can distinguish empty data from service failure; no core interaction depends on clicking a control that has no real implementation.

### Phase 5 — Production readiness, documentation, and CI

**Purpose:** Make the project installable, testable, deployable, and easy to review.

Tasks:

- [x] Add safe `.env.example` files for the required environment variable names, with blank/example values only. Never overwrite or display real `.env` files.
- [x] Validate required production environment variables at startup with a safe, actionable error message that never reveals secret values.
- [x] Confirm production CORS origins, cookie security, API base URL, health endpoint, Vercel rewrite configuration, and failure behavior when MongoDB/email service is unavailable.
- [x] Confirm uploaded files have a persistence strategy appropriate to the host. If the host filesystem is ephemeral, document that limitation and implement an external/object-storage adapter only as a separately scoped task after choosing a provider. Do not claim persistence if it's unverified.
- [x] Add GitHub Actions CI for frontend lint/type-check/build and backend lint/syntax/tests, using a service container or dedicated test DB only if necessary. Keep secrets out of workflow logs.
- [x] Replace the frontend starter README with a real project README: overview, screenshots, features, architecture, stack, environment setup, run commands, validation commands, demo link, and known limitations.
- [x] Update backend README/PRD/code notes so they describe the current implementation and any remaining constraints rather than claiming unverified production status.
- [x] Add an API contract/reference with request examples, auth requirements, role matrix, error format, and local testing instructions.
- [x] Create a seed/demo-data script only if it is safe, deterministic, and clearly disabled for production. Never seed shared production data automatically.
- [x] Run clean-install instructions in a fresh working directory or clean environment where feasible; confirm both applications can be started using documentation.

**Acceptance criteria:** A new developer can follow the README to configure and launch both repos; CI runs the documented checks; secrets are not committed; deployment variables/config are documented; known limitations are clearly stated.

### Phase 6 — One differentiating feature (ONLY AFTER PHASES 0–5)

**Recommended feature:** Project Activity Timeline + Project Health Summary.

This provides a credible differentiator without adding an unrelated AI chatbot or premature real-time architecture.

MVP:

- [x] Add a project-scoped activity/event model for meaningful actions such as project created/updated, member added/role changed/removed, task created/assigned/status changed/completed, note created/updated, and attachment uploaded.
- [x] Record actor, project, action type, target resource, timestamp, and a minimal safe summary. Never record passwords, tokens, secrets, or full sensitive note/file contents.
- [x] Write activity entries in a reliable order with the business action; decide whether audit event persistence must be transactional/compensated and document that choice.
- [x] Add a paginated/filterable activity endpoint protected by project membership and appropriate authorization.
- [x] Show an activity timeline with actor, action, target, and timestamp in the project UI.
- [x] Derive project health indicators from persisted task status and due-date data only if the existing task model supports due dates. If it doesn't, add due-date and optional priority support end-to-end as a separate explicit schema/API/UI migration with validation and tests.
- [x] Add tests for event creation, authorization, pagination, and sensitive-data redaction.

**Acceptance criteria:** The timeline is based on real server-side events, is scoped to authorized project members, has deterministic pagination, and is covered by tests. No hard-coded fake activity or dashboard metrics.

---

## 5. Final definition of done

ProjectCamp is complete enough to showcase when all of the following are true:

- [x] Registration/login/session refresh/logout work end-to-end in the actual deployment.
- [x] Projects persist and are isolated by authorization.
- [x] Membership and per-project roles persist and are enforced by the backend.
- [x] Tasks and subtasks support the documented lifecycle; notes work end-to-end.
- [x] Attachments have validated upload behavior and an explicit, tested storage limitation or persistence strategy.
- [x] Errors, loading states, empty states, retry behavior, and form validation are consistent.
- [x] Frontend lint/type-check/build run; backend tests pass; the relevant checks run in CI.
- [x] No known security issue allows cross-project data access or unauthorized mutation.
- [x] Both repositories have accurate setup/API documentation and environment examples.
- [x] The live demo can be tested using a safe demo account or clearly documented local setup; no real secrets or private data are exposed.
- [x] A reviewer can find meaningful technical decisions, architecture documentation, and tests without guessing.

---

## 6. Progress log

Update this section after each phase with factual results. Do not mark work complete based on generated code alone.

| Date | Phase | Result | Checks run | Remaining blockers |
| --- | --- | --- | --- | --- |
| 2026-10-17 | Roadmap created | Plan prepared from public repo state; local state still needs verification | Public README/package/config/source reviewed | Phase 0 not started |
| 2026-10-18 | Phase 0 — Baseline & Audit | Local state verified (remotes, branches, envs, syntax, contracts, inventory) | `node -c`, `tsc --noEmit`, `eslint .`, remote/git checks | No tests, Phase 1 auth stabilization needed |
| 2026-10-19 | Phase 1 — Auth & Integration | Single HTTP-only cookie contract, robust proxy, automatic token refresh, server logout, forgot/reset password & verification UI added | 15 backend tests passed (`node --test`), frontend `tsc --noEmit` and `eslint .` passed (0 errors) | Phase 2 project/member synchronization |
| 2026-10-19 | Phase 2 — Project & Membership Workflows | End-to-end project persistence with `startDate`, `endDate`, `status`; permission-scoped member management (add by email, dynamic role update, removal); cascading project deletion; dashboard search & empty states | Backend: 31 tests passed (`node --test`, 16 new project tests). Frontend: `tsc --noEmit` (0 errors), `eslint .` (0 errors). | Phase 3 tasks, subtasks, notes, attachments |
| 2026-10-19 | Phase 4 — Backend Reliability & Security Tests | 76 automated tests across 11 suites using Node native test runner; covered role-matrix rules, malformed IDs, token expiration/tampering, stable error envelopes, upload MIME filters, and cross-project isolation | 76 tests passed (`node --test`, 0 failures); frontend `tsc --noEmit` and `eslint .` passed with 0 errors | Frontend UX edge states & Phase 3 task workflows |
| 2026-10-19 | Phase 5 — Production Readiness, Docs & CI | Safe `.env.example` templates, startup environment validation without secret leakage, GitHub Actions CI for backend and frontend, comprehensive `API_DOCUMENTATION.md`, frontend & backend README rewrites, safe dev-only seed script (`seed:dev`), and ephemeral upload documentation | Backend: 78 tests passed (`node --test`); Frontend: `eslint .` (0 errors), `tsc --noEmit` (0 errors), `npm test` (8 tests passed), `npm run build` (success) | None for Phase 5 |
| 2026-10-19 | Phase 6 — Project Activity Timeline & Health Summary | Audited event logging with password/token redaction across projects, members, tasks, and notes; task `dueDate` & `priority` schema/validation/UI; paginated `GET /activities` and computed `GET /health-summary`; full Next.js UI integration with health badge, completion progress, and filterable event stream | Backend: 91 tests passed across 16 suites (`node --test`); Frontend: `tsc --noEmit` (0 errors), `eslint .` (0 errors), `npm test` (8 passed), `npm run build` (success) | Ready for showcase and production deployment |

---

## 7. First task to give Antigravity

Paste this prompt only after opening the workspace that contains both local repositories, or start with the repo you are auditing and explicitly identify its location.

> Read `PROJECTCAMP_IMPLEMENTATION_ROADMAP.md` completely. Execute **Phase 0 only**. Do not edit application source code, install dependencies, change package scripts, or modify Git history during Phase 0. Verify the frontend and backend remotes, branches, working-tree status, project structures, package scripts, environment variable names, API routes, auth/cookie behavior, and existing frontend controls against the local files. Run only currently available safe diagnostic checks and record their actual results. Create a feature inventory marked Works / Broken / Not implemented / Not verified, with evidence and reproduction steps. Identify the three highest-priority confirmed failures and recommend an implementation order. If the local branch has uncommitted changes, preserve them. Update the progress log in this file only after the audit is finished. Stop and report; do not start Phase 1 until I review the audit.

