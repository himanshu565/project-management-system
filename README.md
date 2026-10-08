# Project Management System Backend

This repository contains the REST API for a collaborative project-management
system. The backend is responsible for authentication, project membership,
role-based permissions, tasks, subtasks, project notes, file attachments, and
email-based account flows.

The API is currently implemented with Express and MongoDB. `PRD.md` describes
the intended product requirements, while the source code and this README
describe the behavior that is currently available.

## Current status

The following flows have been implemented and verified locally:

- user registration, login, logout, current-user, token refresh, email
  verification, password change, forgot-password, and reset-password;
- project create, list, search, details, update, and delete;
- project member list, add, role update, and removal;
- task create, list, search, details, update, and delete;
- subtask create, status update, and delete;
- project note create, list, details, update, and delete;
- task attachment uploads;
- health check and consistent API error responses;
- invalid ID validation, missing-resource `404` responses, unauthorized `401`
  responses, and forbidden `403` responses.

The API is the backend service. A frontend may consume it separately and must
send credentials when using the authentication cookies.

## Technology stack

- **Runtime:** Node.js using native ES modules
- **HTTP server:** Express 5
- **Database:** MongoDB with Mongoose
- **Authentication:** JWT access and refresh tokens stored in HTTP-only cookies
- **Password security:** bcrypt
- **Validation:** express-validator
- **Uploads:** Multer, stored under `public/images`
- **Email:** Nodemailer and Mailgen, configured for SMTP/Mailtrap
- **Development:** Nodemon

## How requests are handled

The code follows a layered flow:

```text
Client request
  -> Express app (src/app.js)
  -> Router (src/routes/)
  -> Validation and authentication middleware
  -> Controller (src/controllers/)
  -> Mongoose model (src/models/)
  -> MongoDB
  -> ApiResponse or ApiError
  -> Client
```

Routes map URLs to handlers, middleware validates input and permissions,
controllers coordinate the business operation, and models define the database
rules. This separation is the main way the project is kept maintainable.

## Roles and permissions

Roles are stored per project in `ProjectMember`, not globally on the user. This
allows one person to have different roles in different projects.

| Capability | Admin | Project Admin | Member |
| --- | :---: | :---: | :---: |
| Create, update, or delete projects | Yes | No | No |
| Add, remove, or change project members | Yes | No | No |
| Create, update, or delete tasks | Yes | Yes | No |
| View tasks | Yes | Yes | Yes |
| Create or delete subtasks | Yes | Yes | No |
| Update subtask status | Yes | Yes | Yes |
| Create, update, or delete notes | Yes | No | No |
| View notes | Yes | Yes | Yes |

Project creators automatically receive the `admin` role. Valid project roles
are `admin`, `project_admin`, and `member`.

## API overview

All API routes are prefixed with `/api/v1`.

### Health

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/healthcheck/` | Confirm that the API is running |

### Authentication — `/auth`

| Method | Endpoint | Auth |
| --- | --- | --- |
| POST | `/register` | Public |
| POST | `/login` | Public |
| POST | `/refresh-token` | Public with refresh cookie |
| GET | `/verify-email/:verificationToken` | Public |
| POST | `/forgot-password` | Public |
| POST | `/reset-password/:resetToken` | Public |
| POST | `/logout` | Required |
| GET | `/current-user` | Required |
| POST | `/change-password` | Required |
| POST | `/resend-email-verification` | Required |

### Projects — `/projects`

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/` | List accessible projects; supports `?search=` |
| POST | `/` | Create a project |
| GET | `/:projectId` | Get project details |
| PUT | `/:projectId` | Update a project |
| DELETE | `/:projectId` | Delete a project |
| GET | `/:projectId/members` | List project members |
| POST | `/:projectId/members` | Add a member by email |
| PUT | `/:projectId/members/:userId` | Change a member role |
| DELETE | `/:projectId/members/:userId` | Remove a member |

The add-member body is:

```json
{
  "email": "member@example.com",
  "role": "member"
}
```

### Tasks and subtasks — `/tasks`

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/:projectId` | List tasks; supports `?status=` and `?search=` |
| POST | `/:projectId` | Create a task |
| GET | `/:projectId/t/:taskId` | Get task details |
| PUT | `/:projectId/t/:taskId` | Update a task |
| DELETE | `/:projectId/t/:taskId` | Delete a task |
| POST | `/:projectId/t/:taskId/subtasks` | Create a subtask |
| PUT | `/:projectId/st/:subTaskId` | Update a subtask |
| DELETE | `/:projectId/st/:subTaskId` | Delete a subtask |

Task statuses are `todo`, `in_progress`, and `done`. If `assignedTo` is
provided, it must be a valid MongoDB user ID belonging to an existing user.
Task operations are scoped to their project to prevent cross-project access.

### Notes — `/notes`

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/:projectId` | List project notes |
| POST | `/:projectId` | Create a note |
| GET | `/:projectId/:noteId` | Get note details |
| PUT | `/:projectId/:noteId` | Update a note |
| DELETE | `/:projectId/:noteId` | Delete a note |

Notes support `title`, `content`, and `category`. The detail route is
`/:projectId/:noteId`; the old `/n/:noteId` shape should not be used.

## Getting started

### Prerequisites

- Node.js 18 or newer
- A running MongoDB instance or MongoDB connection string
- An SMTP/Mailtrap account if testing email verification or password reset

### Install dependencies

```bash
npm install
```

### Configure environment variables

Create a `.env` file in the repository root. Do not commit it or share its
values. The application reads these variables:

```dotenv
MONGO_URI=
PORT=8000
CORS_ORIGIN=http://localhost:3000
ACCESS_TOKEN_SECRET=
REFRESH_TOKEN_SECRET=
ACCESS_TOKEN_EXPIRY=
REFRESH_TOKEN_EXPIRY=
MAILTRAP_SMTP_HOST=
MAILTRAP_SMTP_PORT=
MAILTRAP_SMTP_USER=
MAILTRAP_SMTP_PASS=
FORGOT_PASSWORD_REDIRECT_URL=
```

`NEXT_PUBLIC_API_URL` may also be used by a separately developed frontend, but
it is not required by the backend process itself.

### Run the server

Development mode restarts the server when source files change:

```bash
npm run dev
```

Start mode runs the server without Nodemon:

```bash
npm start
```

The default local URL is `http://localhost:8000`. The actual port is controlled
by `PORT`.

## Project structure

```text
src/
├── app.js                    # Express middleware and route mounting
├── server.js                 # Loads environment and starts the server
├── index.js                  # Database startup helper/entry support
├── db/                       # MongoDB connection
├── controllers/              # Request and business-flow handlers
├── middlewares/              # JWT, permissions, validation, errors, uploads
├── models/                   # User, project, member, task, subtask, note
├── routes/                   # Versioned API route definitions
├── utils/                    # Constants, response/error helpers, email
└── validators/               # express-validator rules
public/images/                # Uploaded files served as static files
PRD.md                       # Product requirements and planned behavior
PRojectnotes.md              # Detailed implementation notes and verification log
package.json                 # Scripts and dependencies
```

## Security and reliability conventions

- Never store plaintext passwords; the user model hashes passwords with bcrypt.
- Temporary email and password-reset tokens are hashed before being stored.
- Access tokens are short-lived and refresh tokens are rotated through the
  authentication flow.
- Authentication cookies are HTTP-only. Local development uses `secure: false`
  and `sameSite: lax`; production uses `secure: true` and `sameSite: none`.
- Protected routes use JWT middleware, and project routes use project-specific
  role checks.
- Request bodies are validated before controllers run.
- Uploaded files are limited to 1 MB by the Multer middleware.
- Invalid ObjectIds are rejected before Mongoose queries.
- Child resources are queried with their project ID so resources cannot be
  read or changed through another project.
- Keep secrets in environment variables and use HTTPS in production.

## Working on the project

When adding or changing a feature:

1. Check the requirement in `PRD.md` and the current behavior in
   `PRojectnotes.md`.
2. Add or update the model, validator, controller, and route as appropriate.
3. Preserve the existing `ApiResponse`/`ApiError` response shape.
4. Apply authentication and project-role middleware to every protected route.
5. Keep IDs and child-resource queries scoped to the parent project.
6. Verify both success and failure cases, especially invalid IDs, missing
   resources, invalid input, and insufficient permissions.
7. Remove disposable test records after local verification.

## Verification status

The implementation notes record successful local checks for:

- authentication and token-cookie flows;
- project and member management;
- task, subtask, and note CRUD;
- search and status filtering;
- cross-project protection;
- invalid ID and missing-resource handling;
- syntax checks, editor diagnostics, and `git diff --check`.

There is currently no automated test script in `package.json`. New behavior
should be covered with tests as the project grows.

## Related documentation

- [`PRD.md`](PRD.md) — product requirements, endpoint expectations, and role
  matrix
- [`PRojectnotes.md`](PRojectnotes.md) — detailed code-level notes and the
  latest manual verification record
