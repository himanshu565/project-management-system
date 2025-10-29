/*
  Why this file exists
  ---------------------
  This controller implements the HTTP endpoints for managing Projects and project
  membership. It translates incoming requests into model/service calls and returns
  consistent API responses. The controller coordinates these responsibilities:
  - Parse route/path/query/body inputs.
  - Perform minimal controller-level validation or delegate to validator middleware.
  - Enforce authentication/authorization checks (should be present; add if missing).
  - Call the data layer (models or services) to perform business operations.
  - Use `asyncHandler` to forward errors to centralized error middleware and
    return standardized `ApiResponse` / throw `ApiError` where appropriate.

  Why this design was chosen
  ---------------------------
  - Thin controllers: keep request/response concerns here and move business logic
    to services. This simplifies testing and enforces a single responsibility.
  - `asyncHandler` is used to avoid repetitive try/catch blocks and ensure errors
    bubble to centralized middleware.
  - Aggregation pipelines are used for read-heavy, joined data (e.g., project
    with member counts) to reduce N+1 queries and return pre-joined shapes.

  How to write and maintain code in this file
  -------------------------------------------
  Follow these concrete rules when editing or adding controllers:

  1) Keep controllers thin
     - If you need more than a few lines of DB logic, extract a service function
       (e.g., `src/services/project.service.js`) and call the service from the
       controller. Services own transactions and complex flows.

  2) Validate at the boundary
     - Use `validators/` middleware for request body and parameter validation.
     - Controllers may still assert critical invariants and throw `ApiError(400)`
       for invalid inputs.

  3) Use transactions for multi-step DB operations
     - Examples: creating a project + inserting the corresponding ProjectMember,
       or deleting a project and cascading/deleting dependent tasks.
     - With Mongoose, use session-based transactions when connected to a replica set.

  4) Authorization is required on all modifying endpoints
     - Ensure only project owners/admins can add/remove members, change roles,
       or delete the project. Add `canManageProject(user, project)` helper in
       a common `auth`/`permissions` module and call it from controllers or services.

  5) Return consistent responses and status codes
     - Use `ApiResponse` for successful responses and `ApiError` for errors.
     - Preferred codes: 200 OK, 201 Created, 204 No Content (delete), 400 Bad Request,
       401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict, 500 Server Error.

  6) Projection & pagination
     - For list endpoints, return `{ items, meta }` with paging info.
     - Project only required fields to reduce payload size and DB IO.

  7) Logging & metrics
     - Log important operations (create/delete/role changes) with `userId` and
       `projectId` to help traceability. Emit simple metrics for operation counts.

  8) Testing
     - Unit test controllers by mocking services/models and asserting status
       codes and response shapes.
     - Integration tests should cover entire flows (create, add member, update role,
       delete) against a test DB.

  Quick maintenance checklist (when editing an endpoint)
  ------------------------------------------------------
  - [ ] Is input validated? (validator middleware or controller checks)
  - [ ] Are permissions checked for the current user? (owner/admin vs member)
  - [ ] Are DB writes in a transaction when multiple resources are modified?
  - [ ] Are responses using `ApiResponse` and errors using `ApiError`?
  - [ ] Is the returned payload projected (no sensitive fields)?
  - [ ] Are there unit/integration tests (or TODOs) for the changed behavior?

  For deeper guidance and a prioritized refactor plan, see:
  d:\project-management\src\controllers\project.controllers.revision-notes.md
*/

import { User } from "../models/user.models.js";
import { Project } from "../models/project.models.js";
import { ProjectMember } from "../models/projectmember.models.js";
import { ApiResponse } from "../utils/Api-Response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import mongoose from "mongoose";
import { AvailableUserRole, UserRolesEnum } from "../utils/constants.js";

const getProjects = asyncHandler(async (req, res) => {
  // TODO: Review aggregation pipeline here.
  // - The `$lookup` uses `as: "projects"` but later code unwinds `$project` (singular) — likely a typo/bug.
  // - Ensure the pipeline returns the expected shape. Consider moving this logic to a service
  //   layer and adding unit tests for the aggregation to prevent regressions.
  // - Also consider pagination and projection to limit returned fields for performance.
  const projects = await ProjectMember.aggregate([
    {
      $match: {
        user: new mongoose.Types.ObjectId(req.user._id),
      },
    },
    {
      $lookup: {
        from: "projects",
        localField: "projects",
        foreignField: "_id",
        as: "projects",
        pipeline: [
          {
            $lookup: {
              from: "projectmembers",
              localField: "_id",
              foreignField: "projects",
              as: "projectmembers",
            },
          },
          {
            $addFields: {
              members: {
                $size: "$projectmembers",
              },
            },
          },
        ],
      },
    },
    {
      $unwind: "$projects",
    },
    {
      $project: {
        project: {
          _id: 1,
          name: 1,
          description: 1,
          members: 1,
          createdAt: 1,
          createdBy: 1,
        },
        role: 1,
        _id: 0,
      },
    },
  ]);

  return res
    .status(200)
    .json(new ApiResponse(200, projects, "Projects fetched successfully"));
});

const getProjectById = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const project = await Project.findById(projectId);

  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, project, "Project fetched successfully"));
});

const createProject = asyncHandler(async (req, res) => {
  // TODO: Consider wrapping the following multi-step operation (create project + create ProjectMember)
  // in a DB transaction to ensure atomicity. If using Mongoose with a replica set, use session-based
  // transactions (Project.create(..., { session }) and ProjectMember.create(..., { session })).
  const { name, description } = req.body;

  const project = await Project.create({
    name,
    description,
    createdBy: new mongoose.Types.ObjectId(req.user._id),
  });

  await ProjectMember.create({
    user: new mongoose.Types.ObjectId(req.user._id),
    project: new mongoose.Types.ObjectId(project._id),
    role: UserRolesEnum.ADMIN,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, project, "Project created Successfully"));
});

const updateProject = asyncHandler(async (req, res) => {
  const { name, description } = req.body;
  const { projectId } = req.params;

  const project = await Project.findByIdAndUpdate(
    projectId,
    {
      name,
      description,
    },
    { new: true }
  );

  if (!project) {
    throw new ApiError(404, "Project not found");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, project, "Project updated successfully"));
});

const deleteProject = asyncHandler(async (req, res) => {
  const { projectId } = req.params;

  const project = await Project.findByIdAndDelete(projectId);
  if (!project) {
    throw new ApiError(404, "Project not found");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, project, "Project deleted successfully"));
});

const addMembersToProject = asyncHandler(async (req, res) => {
  const { email, role } = req.body;
  const { projectId } = req.params;
  const user = await User.findOne({ email });

  // TODO: Validate `role` against allowed roles here (or in a validator middleware).
  // The current code upserts the ProjectMember; consider whether upsert should be
  // idempotent (no-op when same role exists) or should return 409/conflict when role differs.

  if (!user) {
    throw new ApiError(404, "User does not exists");
  }

  await ProjectMember.findByIdAndUpdate(
    {
      user: new mongoose.Types.ObjectId(user._id),
      project: new mongoose.Types.ObjectId(projectId),
    },
    {
      user: new mongoose.Types.ObjectId(user._id),
      project: new mongoose.Types.ObjectId(projectId),
      role: role,
    },
    {
      new: true,
      upsert: true,
    }
  );

  return res
    .status(201)
    .json(new ApiResponse(201, {}, "Project member added successfully"));
});

const getProjectMembers = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  // TODO: Bug: `findById` should be called with `projectId`, not `req.params`.
  // Fix: `const project = await Project.findById(projectId);`
  // Also: enforce that the requester has permission to view members (authorization).
  const project = await Project.findById(req.params);

  if (!project) {
    throw new ApiError(404, "Project not found");
  }

  const projectMembers = await ProjectMember.aggregate([
    {
      $match: {
        project: new mongoose.Types.ObjectId(projectId),
      },
    },

    {
      $lookup: {
        from: "users",
        localField: "user",
        foreignField: "_id",
        as: "user",
        pipeline: [
          {
            $project: {
              _id: 1,
              username: 1,
              fullName: 1,
              avatar: 1,
            },
          },
        ],
      },
    },
    {
      $addFields: {
        user: {
          $arrayElemAt: ["$user", 0],
        },
      },
    },
    {
      $project: {
        project: 1,
        user: 1,
        role: 1,
        createdAt: 1,
        updatedAt: 1,
        _id: 0,
      },
    },
  ]);

  return res
    .status(200)
    .json(new ApiResponse(200, projectMembers, "Project members fetched"));
});

const updateMemberRole = asyncHandler(async (req, res) => {
  const { projectId, userId } = req.params;
  const { newRole } = req.body;

  if (!AvailableUserRole.includes(newRole)) {
    throw new ApiError(400, "Invalid Role");
  }

  let projectMember = await ProjectMember.findOne({
    project: new mongoose.Types.ObjectId(projectId),
    user: new mongoose.Types.ObjectId(userId),
  });

  if (!projectMember) {
    throw new ApiError(400, "Project member not found");
  }

  projectMember = await ProjectMember.findByIdAndUpdate(
    projectMember._id,
    {
      role: newRole,
    },
    { new: true }
  );

  if (!projectMember) {
    throw new ApiError(400, "Project member not found");
  }

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        projectMember,
        "Project member role updated successfully"
      )
    );
});

const deleteMember = asyncHandler(async (req, res) => {
  const { projectId, userId } = req.params;

  let projectMember = await ProjectMember.findOne({
    project: new mongoose.Types.ObjectId(projectId),
    user: new mongoose.Types.ObjectId(userId),
  });

  if (!projectMember) {
    throw new ApiError(400, "Project member not found");
  }

  projectMember = await ProjectMember.findByIdAndDelete(projectMember._id);

  if (!projectMember) {
    throw new ApiError(400, "Project member not found");
  }

  return res
    .status(200)
    .json(
      new ApiResponse(200, projectMember, "Project member deleted successfully")
    );
});

export {
  addMembersToProject,
  createProject,
  deleteMember,
  getProjects,
  getProjectById,
  getProjectMembers,
  updateProject,
  deleteProject,
  updateMemberRole,
};
