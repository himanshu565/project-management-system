import test, { describe, it } from "node:test";
import assert from "node:assert/strict";
import mongoose from "mongoose";
import { sanitizeMetadata, recordActivity } from "../src/utils/activity-logger.js";
import { Activity } from "../src/models/activity.models.js";
import { Task } from "../src/models/task.models.js";
import { Project } from "../src/models/project.models.js";
import { ProjectMember } from "../src/models/projectmember.models.js";
import {
  createTaskValidator,
  updateTaskValidator,
} from "../src/validators/index.js";
import {
  getProjectActivities,
  getProjectHealthSummary,
} from "../src/controllers/project.controllers.js";
import {
  createMockResponse,
  generateTestToken,
  runValidator,
} from "./test-utils.js";
import app from "../src/app.js";
import {
  ActivityActionEnum,
  ActivityResourceEnum,
  TaskPriorityEnum,
  taskStatusEnum,
  UserRolesEnum,
} from "../src/utils/constants.js";

describe("Phase 6: Activity Logger & Sensitive Data Redaction", () => {
  it("sanitizeMetadata strictly removes passwords, tokens, and secrets", () => {
    const raw = {
      userEmail: "test@example.com",
      password: "SuperSecretPassword123!",
      userPassword: "another_secret",
      accessToken: "jwt.access.token.value",
      refreshToken: "jwt.refresh.token.value",
      verificationToken: "verify_token_123",
      resetToken: "reset_token_456",
      authCookie: "s:cookie_val",
      taskTitle: "Safe title",
      priority: "high",
    };

    const sanitized = sanitizeMetadata(raw);

    assert.equal(sanitized.userEmail, "test@example.com");
    assert.equal(sanitized.taskTitle, "Safe title");
    assert.equal(sanitized.priority, "high");
    assert.equal(sanitized.password, undefined);
    assert.equal(sanitized.userPassword, undefined);
    assert.equal(sanitized.accessToken, undefined);
    assert.equal(sanitized.refreshToken, undefined);
    assert.equal(sanitized.verificationToken, undefined);
    assert.equal(sanitized.resetToken, undefined);
    assert.equal(sanitized.authCookie, undefined);
  });

  it("sanitizeMetadata truncates strings exceeding 200 characters to prevent unbounded storage", () => {
    const longString = "A".repeat(300);
    const sanitized = sanitizeMetadata({ noteContent: longString });
    assert.ok(sanitized.noteContent.length <= 200);
    assert.ok(sanitized.noteContent.endsWith("..."));
  });

  it("recordActivity gracefully validates required inputs", async () => {
    // Missing required parameters should return null without throwing
    const res1 = await recordActivity({});
    assert.equal(res1, null);

    const res2 = await recordActivity({
      project: new mongoose.Types.ObjectId(),
      actor: new mongoose.Types.ObjectId(),
      // missing actionType, resourceType, summary
    });
    assert.equal(res2, null);
  });
});

describe("Phase 6: Task Due Date & Priority Validation", () => {
  it("createTaskValidator accepts valid ISO8601 dueDate and priority", async () => {
    const { result } = await runValidator(createTaskValidator, {
      title: "Valid task with deadline",
      dueDate: "2026-11-15T00:00:00.000Z",
      priority: "urgent",
    });
    assert.equal(result.isEmpty(), true);
  });

  it("createTaskValidator rejects invalid priority not in enum", async () => {
    const { result } = await runValidator(createTaskValidator, {
      title: "Task with bad priority",
      priority: "super_critical_invalid",
    });
    assert.equal(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "priority"));
  });

  it("createTaskValidator rejects non-ISO8601 dueDate", async () => {
    const { result } = await runValidator(createTaskValidator, {
      title: "Task with bad date",
      dueDate: "not-a-real-date",
    });
    assert.equal(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "dueDate"));
  });

  it("updateTaskValidator accepts optional priority and dueDate", async () => {
    const { result } = await runValidator(updateTaskValidator, {
      priority: "low",
      dueDate: "2026-12-31T23:59:59.000Z",
    });
    assert.equal(result.isEmpty(), true);
  });
});

describe("Phase 6: Project Health Summary Calculation", () => {
  it("getProjectHealthSummary computes 0% and 'Not Started' for projects with no tasks", async () => {
    const projectId = new mongoose.Types.ObjectId().toString();
    const mockProject = {
      _id: projectId,
      name: "Empty Project",
      status: "Planning",
      startDate: "2026-10-01",
      endDate: "2026-12-31",
    };

    const origProjectFindById = Project.findById;
    const origTaskFind = Task.find;
    const origMemberCount = ProjectMember.countDocuments;

    Project.findById = (id) => ({
      select: () => Promise.resolve(mockProject),
    });
    Task.find = () => ({
      select: () => Promise.resolve([]),
    });
    ProjectMember.countDocuments = () => Promise.resolve(1);

    try {
      const req = {
        params: { projectId },
        user: { _id: new mongoose.Types.ObjectId() },
      };
      const res = createMockResponse();

      await getProjectHealthSummary(req, res);

      assert.equal(res.statusCode, 200);
      assert.equal(res.body.success, true);
      const data = res.body.data;
      assert.equal(data.projectName, "Empty Project");
      assert.equal(data.healthStatus, "Not Started");
      assert.equal(data.completionPercentage, 0);
      assert.equal(data.tasks.total, 0);
      assert.equal(data.tasks.completed, 0);
      assert.equal(data.memberCount, 1);
    } finally {
      Project.findById = origProjectFindById;
      Task.find = origTaskFind;
      ProjectMember.countDocuments = origMemberCount;
    }
  });

  it("getProjectHealthSummary computes 100% and 'Completed' when all tasks are done", async () => {
    const projectId = new mongoose.Types.ObjectId().toString();
    const mockProject = {
      _id: projectId,
      name: "Finished Project",
      status: "Completed",
    };

    const mockTasks = [
      { title: "Task 1", status: "done", priority: "high" },
      { title: "Task 2", status: "done", priority: "medium" },
    ];

    const origProjectFindById = Project.findById;
    const origTaskFind = Task.find;
    const origMemberCount = ProjectMember.countDocuments;

    Project.findById = () => ({ select: () => Promise.resolve(mockProject) });
    Task.find = () => ({ select: () => Promise.resolve(mockTasks) });
    ProjectMember.countDocuments = () => Promise.resolve(2);

    try {
      const req = { params: { projectId }, user: { _id: new mongoose.Types.ObjectId() } };
      const res = createMockResponse();

      await getProjectHealthSummary(req, res);

      assert.equal(res.statusCode, 200);
      const data = res.body.data;
      assert.equal(data.completionPercentage, 100);
      assert.equal(data.healthStatus, "Completed");
      assert.equal(data.tasks.total, 2);
      assert.equal(data.tasks.completed, 2);
      assert.equal(data.tasks.overdue, 0);
    } finally {
      Project.findById = origProjectFindById;
      Task.find = origTaskFind;
      ProjectMember.countDocuments = origMemberCount;
    }
  });

  it("getProjectHealthSummary accurately detects overdue tasks and flags 'At Risk' or 'Critical'", async () => {
    const projectId = new mongoose.Types.ObjectId().toString();
    const mockProject = {
      _id: projectId,
      name: "Active Project",
      status: "In Progress",
    };

    const pastDate = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000); // 5 days ago
    const futureDate = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000); // 10 days ahead

    const mockTasks = [
      { title: "Task Done", status: "done", priority: "low" },
      { title: "Task Overdue", status: "in_progress", priority: "urgent", dueDate: pastDate },
      { title: "Task On Track", status: "todo", priority: "medium", dueDate: futureDate },
    ];

    const origProjectFindById = Project.findById;
    const origTaskFind = Task.find;
    const origMemberCount = ProjectMember.countDocuments;

    Project.findById = () => ({ select: () => Promise.resolve(mockProject) });
    Task.find = () => ({ select: () => Promise.resolve(mockTasks) });
    ProjectMember.countDocuments = () => Promise.resolve(3);

    try {
      const req = { params: { projectId }, user: { _id: new mongoose.Types.ObjectId() } };
      const res = createMockResponse();

      await getProjectHealthSummary(req, res);

      assert.equal(res.statusCode, 200);
      const data = res.body.data;
      assert.equal(data.tasks.total, 3);
      assert.equal(data.tasks.completed, 1);
      assert.equal(data.tasks.inProgress, 1);
      assert.equal(data.tasks.todo, 1);
      assert.equal(data.tasks.overdue, 1);
      assert.equal(data.completionPercentage, 33);
      assert.equal(data.healthStatus, "Critical");
      assert.equal(data.priorityBreakdown.urgent, 1);
      assert.equal(data.priorityBreakdown.low, 1);
      assert.equal(data.priorityBreakdown.medium, 1);
    } finally {
      Project.findById = origProjectFindById;
      Task.find = origTaskFind;
      ProjectMember.countDocuments = origMemberCount;
    }
  });
});

describe("Phase 6: Project Activities Endpoint & Pagination", () => {
  it("getProjectActivities returns deterministic pagination and populated actor details", async () => {
    const projectId = new mongoose.Types.ObjectId().toString();
    const actorId = new mongoose.Types.ObjectId();

    const mockActivities = [
      {
        _id: new mongoose.Types.ObjectId(),
        project: projectId,
        actor: {
          _id: actorId,
          username: "alice",
          fullName: "Alice Developer",
          email: "alice@example.com",
        },
        actionType: ActivityActionEnum.TASK_CREATED,
        resourceType: ActivityResourceEnum.TASK,
        summary: "Created task 'Implement OAuth'",
        createdAt: new Date(),
      },
    ];

    const origActivityFind = Activity.find;
    const origActivityCount = Activity.countDocuments;

    Activity.find = () => ({
      sort: () => ({
        skip: () => ({
          limit: () => ({
            populate: () => Promise.resolve(mockActivities),
          }),
        }),
      }),
    });
    Activity.countDocuments = () => Promise.resolve(1);

    try {
      const req = {
        params: { projectId },
        query: { page: "1", limit: "10" },
        user: { _id: actorId },
      };
      const res = createMockResponse();

      await getProjectActivities(req, res);

      assert.equal(res.statusCode, 200);
      assert.equal(res.body.success, true);
      const data = res.body.data;
      assert.equal(data.activities.length, 1);
      assert.equal(data.activities[0].actionType, ActivityActionEnum.TASK_CREATED);
      assert.equal(data.activities[0].actor.username, "alice");
      assert.equal(data.pagination.total, 1);
      assert.equal(data.pagination.page, 1);
      assert.equal(data.pagination.limit, 10);
      assert.equal(data.pagination.totalPages, 1);
      assert.equal(data.pagination.hasNextPage, false);
      assert.equal(data.pagination.hasPrevPage, false);
    } finally {
      Activity.find = origActivityFind;
      Activity.countDocuments = origActivityCount;
    }
  });
});
