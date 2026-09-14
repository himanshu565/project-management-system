# project-management-system
# Project Camp Backend

A RESTful API service for collaborative project management. Teams can organize projects, manage tasks with subtasks, keep project notes, and handle authentication with role-based access control.

## Features

- **Authentication** — registration with email verification, JWT-based login, access/refresh token rotation, forgot/reset password
- **Role-based access control** — three-tier permission system (Admin, Project Admin, Member)
- **Project management** — create, list, update, and delete projects; manage team members and their roles
- **Task management** — tasks with status tracking (Todo → In Progress → Done), assignment to team members, file attachments
- **Subtasks** — break tasks down further, with completion tracking
- **Project notes** — admin-managed notes scoped to each project

## Tech Stack

- **Runtime:** Node.js , express
- **Auth:** JWT (access + refresh tokens)
- **File uploads:** Multer
<!-- Fill in: framework (Express? Fastify?), database (MongoDB/Mongoose? PostgreSQL?), and any other libraries you used -->

## Permission Matrix

| Feature                    | Admin | Project Admin | Member |
| --------------------------- | :---: | :------------: | :----: |
| Create project              |  ✓   |       ✗        |   ✗    |
| Update / delete project     |  ✓   |       ✗        |   ✗    |
| Manage project members      |  ✓   |       ✗        |   ✗    |
| Create / update / delete tasks |  ✓   |       ✓        |   ✗    |
| View tasks                  |  ✓   |       ✓        |   ✓    |
| Create / delete subtasks    |  ✓   |       ✓        |   ✗    |
| Update subtask status       |  ✓   |       ✓        |   ✓    |
| Create / update / delete notes |  ✓   |       ✗        |   ✗    |
| View notes                  |  ✓   |       ✓        |   ✓    |

## API Overview

### Auth — `/api/v1/auth`
| Method | Endpoint | Description |
|---|---|---|
| POST | `/register` | Register a new user |
| POST | `/login` | Authenticate and receive tokens |
| POST | `/logout` | Log out (secured) |
| GET | `/current-user` | Get the logged-in user (secured) |
| POST | `/change-password` | Change password (secured) |
| POST | `/refresh-token` | Refresh access token |
| GET | `/verify-email/:verificationToken` | Verify email address |
| POST | `/forgot-password` | Request a password reset |
| POST | `/reset-password/:resetToken` | Reset password with token |
| POST | `/resend-email-verification` | Resend verification email (secured) |

### Projects — `/api/v1/projects`
| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | List projects the user has access to |
| POST | `/` | Create a project |
| GET | `/:projectId` | Get project details |
| PUT | `/:projectId` | Update project (Admin) |
| DELETE | `/:projectId` | Delete project (Admin) |
| GET | `/:projectId/members` | List project members |
| POST | `/:projectId/members` | Add a member (Admin) |
| PUT | `/:projectId/members/:userId` | Update a member's role (Admin) |
| DELETE | `/:projectId/members/:userId` | Remove a member (Admin) |

### Tasks — `/api/v1/tasks`
| Method | Endpoint | Description |
|---|---|---|
| GET | `/:projectId` | List tasks in a project |
| POST | `/:projectId` | Create a task (Admin / Project Admin) |
| GET | `/:projectId/t/:taskId` | Get task details |
| PUT | `/:projectId/t/:taskId` | Update a task (Admin / Project Admin) |
| DELETE | `/:projectId/t/:taskId` | Delete a task (Admin / Project Admin) |
| POST | `/:projectId/t/:taskId/subtasks` | Create a subtask (Admin / Project Admin) |
| PUT | `/:projectId/st/:subTaskId` | Update a subtask |
| DELETE | `/:projectId/st/:subTaskId` | Delete a subtask (Admin / Project Admin) |

### Notes — `/api/v1/notes`
| Method | Endpoint | Description |
|---|---|---|
| GET | `/:projectId` | List notes in a project |
| POST | `/:projectId` | Create a note (Admin) |
| GET | `/:projectId/n/:noteId` | Get note details |
| PUT | `/:projectId/n/:noteId` | Update a note (Admin) |
| DELETE | `/:projectId/n/:noteId` | Delete a note (Admin) |

### Health — `/api/v1/healthcheck`
| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Check API status |

## Getting Started

### Prerequisites
<!-- e.g. Node.js 18+, a running MongoDB instance, npm -->
- Node.js (version)
- (Database) running locally or a connection string

### Installation

```bash
git clone https://github.com/himanshu565/project-management-system.git
cd project-management-system
npm install
```

### Environment Variables

Create a `.env` file in the root (see `.env.example` for the required keys):

```
# fill in the actual variable names your app expects, e.g.
PORT=
DATABASE_URL=
JWT_ACCESS_SECRET=
JWT_REFRESH_SECRET=
EMAIL_SERVICE_API_KEY=
```

### Running the server

```bash
npm run dev
```

The API will be available at `http://localhost:<PORT>`.

## Project Structure

```
project-management-system/
├── src/
├── public/images/     # uploaded file attachments
├── PRD.md             # product requirements
├── CODEBASE-NOTES.md  # internal dev notes
└── package.json
```

## Security Notes

- Passwords are never stored in plaintext; auth uses JWT access + refresh tokens
- All write operations are gated by role-based middleware per the permission matrix above
- File uploads are handled through Multer with size/type validation


## License
