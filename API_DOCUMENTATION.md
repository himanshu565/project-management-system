# ProjectCamp Backend API Specification & Contract Reference

This document defines the formal HTTP API contract for the ProjectCamp REST API (`/api/v1`). It details authentication contracts, standard response envelopes, role-based access control (RBAC) rules, endpoint schemas, error codes, and local testing instructions.

---

## 1. System Architecture & Base URLs

- **Local Base URL:** `http://localhost:8000/api/v1`
- **Reverse Proxy / Frontend Path:** Next.js proxies browser calls through `/api/v1/*` to avoid CORS issues in local development.
- **Protocol:** HTTP / JSON REST
- **Credentials:** Cookie-based session (`credentials: "include"`)

---

## 2. Standard Response & Error Envelopes

Every API response follows a consistent JSON envelope. Clients should parse responses through this structure.

### 2.1 Success Response Envelope (`ApiResponse`)

```json
{
  "statusCode": 200,
  "data": { ... },
  "message": "Resource retrieved successfully",
  "success": true
}
```

- `statusCode` (integer): HTTP status code (200, 201, etc.).
- `data` (object | array | null): The primary payload.
- `message` (string): Human-readable status message.
- `success` (boolean): Always `true` on successful operations.

### 2.2 Error Response Envelope (`ApiError`)

```json
{
  "statusCode": 400,
  "data": null,
  "message": "Invalid credentials or validation failed",
  "success": false,
  "errors": [
    {
      "field": "email",
      "message": "Invalid email address"
    }
  ]
}
```

- `statusCode` (integer): HTTP error status (400, 401, 403, 404, 409, 500).
- `data` (null): Always `null` on errors.
- `message` (string): Descriptive error message safe for user display.
- `success` (boolean): Always `false`.
- `errors` (array): List of specific validation or sub-errors.

---

## 3. Authentication & Cookie Contract

ProjectCamp uses **HTTP-only, Secure Cookies** for token management. Tokens are never exposed in JavaScript `localStorage`, defending against XSS attacks.

| Cookie Name | Expiration | Attributes | Description |
| :--- | :--- | :--- | :--- |
| `accessToken` | 15m - 1d (`ACCESS_TOKEN_EXPIRY`) | `HttpOnly`, `SameSite=Lax`, `Secure` (prod), `Path=/` | Short-lived JWT verifying user identity. |
| `refreshToken` | 10d (`REFRESH_TOKEN_EXPIRY`) | `HttpOnly`, `SameSite=Lax`, `Secure` (prod), `Path=/` | Long-lived JWT stored hashed in MongoDB to issue new access tokens. |

### Client Contract:
- Every browser request must include `credentials: "include"`.
- If an API returns `401 Unauthorized`, the client calls `POST /api/v1/users/refresh-token`.
- If refresh returns `401` or `403`, the user's session is expired, and the client redirects to the login screen.

---

## 4. Role-Based Access Control (RBAC) Matrix

ProjectCamp enforces project-scoped roles stored in the `ProjectMember` collection.

| Endpoint Action | Required Role | Failure Code | Note |
| :--- | :--- | :--- | :--- |
| Create Project | Authenticated User | `401` | Creator is automatically made `admin`. |
| View Project Details | `admin`, `project_admin`, `member` | `403` / `404` | Non-members cannot access. |
| Update Project Meta | `admin`, `project_admin` | `403` | Members cannot edit project info. |
| Delete Project | `admin` (Creator) | `403` | Irreversible; cascades to members, tasks, notes. |
| Add Project Member | `admin`, `project_admin` | `403` | Add by email; must be registered user. |
| Update Member Role | `admin`, `project_admin` | `403` | Cannot alter project creator/admin. |
| Remove Member | `admin`, `project_admin` | `403` | Creator cannot be removed. |
| View Tasks / Notes | `admin`, `project_admin`, `member` | `403` | Scoped to project members only. |
| Create / Edit Tasks | `admin`, `project_admin`, `member` | `403` | Validated against project membership. |
| Delete Tasks / Notes | `admin`, `project_admin` | `403` | Member deletion restricted. |

---

## 5. API Endpoints Reference

### 5.1 Health Check

#### `GET /api/v1/health`
- **Auth:** None
- **Response `200`:**
  ```json
  {
    "statusCode": 200,
    "data": { "status": "ok", "timestamp": "2026-10-19T07:15:00.000Z" },
    "message": "Service is healthy",
    "success": true
  }
  ```

---

### 5.2 Authentication & User Management

#### `POST /api/v1/users/register`
- **Auth:** None
- **Body:**
  ```json
  {
    "username": "johndoe",
    "email": "john@example.com",
    "password": "Password123!",
    "fullName": "John Doe"
  }
  ```
- **Response `201`:** User created. Sends verification email if SMTP is configured.

#### `POST /api/v1/users/login`
- **Auth:** None
- **Body:**
  ```json
  {
    "email": "john@example.com",
    "password": "Password123!"
  }
  ```
- **Response `200`:** Sets `accessToken` and `refreshToken` cookies. Returns user object.

#### `POST /api/v1/users/logout`
- **Auth:** Required (Cookie)
- **Response `200`:** Clears `accessToken` and `refreshToken` cookies, invalidates refresh token in DB.

#### `POST /api/v1/users/refresh-token`
- **Auth:** `refreshToken` Cookie
- **Response `200`:** Rotates access token and sets new cookie.

#### `GET /api/v1/users/current-user`
- **Auth:** Required (Cookie)
- **Response `200`:** Returns authenticated user profile (`_id`, `username`, `email`, `fullName`, `avatar`, `isEmailVerified`).

#### `GET /api/v1/users/verify-email/:verificationToken`
- **Auth:** None
- **Response `200`:** Marks user `isEmailVerified: true`.

#### `POST /api/v1/users/forgot-password`
- **Auth:** None
- **Body:** `{ "email": "john@example.com" }`
- **Response `200`:** Sends reset link containing token to user email.

#### `POST /api/v1/users/reset-password/:resetToken`
- **Auth:** None
- **Body:** `{ "newPassword": "NewPassword123!" }`
- **Response `200`:** Updates password hash and clears reset token.

---

### 5.3 Projects

#### `GET /api/v1/projects`
- **Auth:** Required
- **Response `200`:** Returns array of projects the authenticated user belongs to.

#### `POST /api/v1/projects`
- **Auth:** Required
- **Body:**
  ```json
  {
    "name": "Q4 Infrastructure Migration",
    "description": "Migrate core microservices to Kubernetes",
    "status": "In Progress",
    "startDate": "2026-10-01",
    "endDate": "2026-12-31"
  }
  ```
- **Response `201`:** Returns created project. Caller is assigned role `admin`.

#### `GET /api/v1/projects/:projectId`
- **Auth:** Project Member (`admin`, `project_admin`, `member`)
- **Response `200`:** Returns project entity.

#### `PUT /api/v1/projects/:projectId`
- **Auth:** `admin` or `project_admin`
- **Body:** `{ "name": "New Name", "description": "...", "status": "Done" }`
- **Response `200`:** Returns updated project entity.

#### `DELETE /api/v1/projects/:projectId`
- **Auth:** `admin` only
- **Response `200`:** Deletes project, project members, tasks, subtasks, and notes.

---

### 5.4 Project Members

#### `GET /api/v1/projects/:projectId/members`
- **Auth:** Project Member
- **Response `200`:** Returns list of members with user profiles and roles.

#### `POST /api/v1/projects/:projectId/members`
- **Auth:** `admin` or `project_admin`
- **Body:**
  ```json
  {
    "email": "colleague@example.com",
    "role": "member"
  }
  ```
- **Response `201`:** Adds existing user to project. Fails if user not found (`404`) or duplicate (`409`).

#### `PUT /api/v1/projects/:projectId/members/:memberId`
- **Auth:** `admin` or `project_admin`
- **Body:** `{ "role": "project_admin" }`
- **Response `200`:** Updates member role. Cannot demote project creator.

#### `DELETE /api/v1/projects/:projectId/members/:memberId`
- **Auth:** `admin` or `project_admin`
- **Response `200`:** Removes member from project. Cannot remove project creator.

---

### 5.5 Tasks & Subtasks

#### `GET /api/v1/tasks/:projectId`
- **Auth:** Project Member
- **Response `200`:** Returns array of tasks in the project.

#### `POST /api/v1/tasks/:projectId`
- **Auth:** Project Member
- **Body:**
  ```json
  {
    "title": "Set up CI pipeline",
    "description": "Configure GitHub Actions workflow for backend",
    "status": "todo",
    "priority": "high",
    "dueDate": "2026-11-15T00:00:00.000Z",
    "assignedTo": "64f1a2b3c4d5e6f7a8b9c0d1"
  }
  ```
- **Response `201`:** Returns created task.

#### `GET /api/v1/tasks/:projectId/:taskId`
- **Auth:** Project Member
- **Response `200`:** Returns task details with subtasks and attachments.

#### `PUT /api/v1/tasks/:projectId/:taskId`
- **Auth:** Project Member
- **Body:** `{ "status": "in_progress", "title": "Updated title", "priority": "urgent", "dueDate": "2026-11-20T00:00:00.000Z" }`
- **Response `200`:** Returns updated task.

#### `DELETE /api/v1/tasks/:projectId/:taskId`
- **Auth:** `admin` or `project_admin`
- **Response `200`:** Deletes task and child subtasks.

#### `POST /api/v1/tasks/:taskId/st`
- **Auth:** Project Member
- **Body:** `{ "title": "Add lint check step" }`
- **Response `201`:** Creates subtask under parent task.

#### `PUT /api/v1/tasks/:taskId/st/:subTaskId`
- **Auth:** Project Member
- **Body:** `{ "isCompleted": true }`
- **Response `200`:** Toggles subtask completion status.

#### `DELETE /api/v1/tasks/:taskId/st/:subTaskId`
- **Auth:** Project Member
- **Response `200`:** Deletes subtask.

---

### 5.6 Project Notes

#### `GET /api/v1/notes/:projectId`
- **Auth:** Project Member
- **Response `200`:** Returns list of notes in project.

#### `POST /api/v1/notes/:projectId`
- **Auth:** Project Member
- **Body:**
  ```json
  {
    "title": "Architecture Decisions",
    "content": "We chose MongoDB Atlas with Mongoose for dynamic schema support.",
    "category": "Architecture"
  }
  ```
- **Response `201`:** Returns created note.

#### `GET /api/v1/notes/:projectId/:noteId`
- **Auth:** Project Member
- **Response `200`:** Returns single note by ID.

#### `PUT /api/v1/notes/:projectId/:noteId`
- **Auth:** Project Member
- **Body:** `{ "content": "Updated content" }`
- **Response `200`:** Updates note content.

#### `DELETE /api/v1/notes/:projectId/:noteId`
- **Auth:** `admin` or `project_admin`
- **Response `200`:** Deletes note.

---

### 5.7 Project Activity & Health Summary

#### `GET /api/v1/projects/:projectId/activities`
- **Auth:** Project Member (`admin`, `project_admin`, `member`)
- **Query Parameters:**
  - `page` (optional integer, default `1`): Current page number.
  - `limit` (optional integer, default `20`): Page size limit (maximum `50`).
  - `resourceType` (optional string): Filter events by resource type (`project`, `member`, `task`, `subtask`, `note`).
- **Response `200`:** Returns paginated list of audited activity events. All sensitive properties (passwords, tokens, secrets, cookies) are automatically stripped, and long text values are truncated.
  ```json
  {
    "statusCode": 200,
    "data": {
      "activities": [
        {
          "_id": "67b5f1a2c3d4e5f6a7b8c9d0",
          "project": "64f1a2b3c4d5e6f7a8b9c0d1",
          "actor": {
            "_id": "64f1a2b3c4d5e6f7a8b9c0d2",
            "username": "alice_admin",
            "fullName": "Alice Smith",
            "avatar": { "url": "https://..." }
          },
          "actionType": "TASK_CREATED",
          "resourceType": "task",
          "resourceId": "64f1a2b3c4d5e6f7a8b9c0d3",
          "summary": "Alice Smith created task \"Set up CI pipeline\"",
          "metadata": { "priority": "high", "dueDate": "2026-11-15T00:00:00.000Z" },
          "createdAt": "2026-10-19T07:20:00.000Z"
        }
      ],
      "pagination": {
        "total": 1,
        "page": 1,
        "limit": 20,
        "totalPages": 1
      }
    },
    "message": "Project activities retrieved successfully",
    "success": true
  }
  ```

#### `GET /api/v1/projects/:projectId/health-summary`
- **Auth:** Project Member (`admin`, `project_admin`, `member`)
- **Response `200`:** Returns real-time computed project health metrics derived from persisted task statuses, due dates, priorities, and project schedule.
  ```json
  {
    "statusCode": 200,
    "data": {
      "projectId": "64f1a2b3c4d5e6f7a8b9c0d1",
      "projectName": "Q4 Infrastructure Migration",
      "projectStatus": "In Progress",
      "healthStatus": "On Track",
      "healthReason": "All open tasks are within scheduled deadlines",
      "completionPercentage": 60,
      "tasks": {
        "total": 5,
        "completed": 3,
        "inProgress": 1,
        "todo": 1,
        "overdue": 0,
        "dueSoon": 1
      },
      "priorityBreakdown": {
        "low": 0,
        "medium": 2,
        "high": 2,
        "urgent": 1
      },
      "schedule": {
        "startDate": "2026-10-01",
        "endDate": "2026-12-31",
        "isOverdue": false
      },
      "memberCount": 3
    },
    "message": "Project health summary retrieved successfully",
    "success": true
  }
  ```

---

## 6. File Uploads & Known Ephemeral Storage Limitations

- **Upload Endpoint:** `POST /api/v1/tasks/:taskId/attachments` (multipart/form-data)
- **Size Limit:** Max **1 MB** per file.
- **Allowed MIME Types:** `image/jpeg`, `image/png`, `image/webp`, `image/gif`, `application/pdf`, `text/plain`.
- **Known Production Limitation:** Uploads are currently saved to the local filesystem at `./public/images`. In serverless or ephemeral container deployments (Vercel, Render, Heroku Dynos), local filesystem modifications are discarded on instance restart or failover. Production multi-instance deployments require an external object-storage adapter (AWS S3, Cloudinary, or GCP Cloud Storage).

---

## 7. Local Development & Verification

### Running Automated Tests
The backend test suite uses Node's native test runner (`node --test`) with 0 external mock dependencies.

```bash
npm test
```

### Seeding Development Data
Populate the database with deterministic demo users, project, tasks, and notes:

```bash
npm run seed:dev
```
*(Strictly disabled when `NODE_ENV=production`)*

