import dotenv from "dotenv";
import mongoose from "dotenv"; // Will use mongoose below
import mongooseInstance from "mongoose";
import { User } from "../src/models/user.models.js";
import { Project } from "../src/models/project.models.js";
import { ProjectMember } from "../src/models/projectmember.models.js";
import { Task } from "../src/models/task.models.js";
import { Subtask } from "../src/models/subtask.models.js";
import { ProjectNote } from "../src/models/note.models.js";
import { Activity } from "../src/models/activity.models.js";
import {
  UserRolesEnum,
  ProjectStatusEnum,
  taskStatusEnum,
  TaskPriorityEnum,
  ActivityActionEnum,
  ActivityResourceEnum,
} from "../src/utils/constants.js";

dotenv.config();

// Production Guard: Never run seed in production
if (process.env.NODE_ENV === "production") {
  console.error("FATAL: Seeding is strictly disabled in production environment (NODE_ENV=production).");
  process.exit(1);
}

const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI;

if (!mongoUri) {
  console.error("FATAL: MONGO_URI or MONGODB_URI is not defined in environment.");
  process.exit(1);
}

// Safety check against running against production-labeled clusters
if (mongoUri.toLowerCase().includes("prod") && !mongoUri.toLowerCase().includes("nonprod")) {
  console.error("FATAL: Connection URI contains 'prod'. Aborting seed script to prevent accidental data corruption.");
  process.exit(1);
}

async function seed() {
  try {
    console.log("Connecting to database for seeding...");
    await mongooseInstance.connect(mongoUri);
    console.log("Connected to MongoDB successfully.");

    const demoEmails = ["admin@example.com", "member@example.com"];
    console.log(`Cleaning up existing demo users: ${demoEmails.join(", ")}...`);

    const existingUsers = await User.find({ email: { $in: demoEmails } });
    const userIds = existingUsers.map((u) => u._id);

    if (userIds.length > 0) {
      const existingProjects = await Project.find({ createdBy: { $in: userIds } });
      const projectIds = existingProjects.map((p) => p._id);

      await Subtask.deleteMany({ createdBy: { $in: userIds } });
      await Task.deleteMany({ project: { $in: projectIds } });
      await ProjectNote.deleteMany({ project: { $in: projectIds } });
      await ProjectMember.deleteMany({ user: { $in: userIds } });
      await Activity.deleteMany({ project: { $in: projectIds } });
      await Project.deleteMany({ _id: { $in: projectIds } });
      await User.deleteMany({ _id: { $in: userIds } });
      console.log("Cleaned up existing demo records.");
    }

    // 1. Create Demo Users
    console.log("Creating demo users...");
    const adminUser = await User.create({
      username: "demoadmin",
      email: "admin@example.com",
      password: "Password123!",
      fullName: "Demo Admin",
      isEmailVerified: true,
    });

    const memberUser = await User.create({
      username: "demomember",
      email: "member@example.com",
      password: "Password123!",
      fullName: "Demo Member",
      isEmailVerified: true,
    });

    // 2. Create Demo Project
    console.log("Creating demo project...");
    const project = await Project.create({
      name: "Alpha Platform Launch",
      description: "Next-generation project management platform with end-to-end RBAC and task workflows.",
      status: ProjectStatusEnum.IN_PROGRESS,
      startDate: "2026-10-01",
      endDate: "2026-12-31",
      createdBy: adminUser._id,
    });

    // 3. Add Project Members
    console.log("Adding project members...");
    await ProjectMember.create([
      {
        user: adminUser._id,
        project: project._id,
        role: UserRolesEnum.ADMIN,
      },
      {
        user: memberUser._id,
        project: project._id,
        role: UserRolesEnum.MEMBER,
      },
    ]);

    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;

    // 4. Create Demo Tasks
    console.log("Creating demo tasks...");
    const task1 = await Task.create({
      title: "Finalize system architecture",
      description: "Review system components, security middleware, and database indexing strategies.",
      project: project._id,
      assignedTo: adminUser._id,
      assignedBy: adminUser._id,
      status: taskStatusEnum.DONE,
      priority: TaskPriorityEnum.HIGH,
      dueDate: new Date(now + 7 * day),
    });

    const task2 = await Task.create({
      title: "Implement RBAC permissions",
      description: "Ensure project admin and member role isolation across all project child routes.",
      project: project._id,
      assignedTo: adminUser._id,
      assignedBy: adminUser._id,
      status: taskStatusEnum.IN_PROGRESS,
      priority: TaskPriorityEnum.URGENT,
      dueDate: new Date(now + 2 * day),
    });

    const task3 = await Task.create({
      title: "Frontend integration testing",
      description: "Verify cookie-based session persistence, real-time error states, and responsive UI.",
      project: project._id,
      assignedTo: memberUser._id,
      assignedBy: adminUser._id,
      status: taskStatusEnum.TODO,
      priority: TaskPriorityEnum.MEDIUM,
      dueDate: new Date(now + 14 * day),
    });

    // 5. Create Demo Subtasks
    console.log("Creating demo subtasks...");
    await Subtask.create([
      {
        title: "Review API schema envelope",
        task: task1._id,
        isCompleted: true,
        createdBy: adminUser._id,
      },
      {
        title: "Verify DB indexes",
        task: task1._id,
        isCompleted: true,
        createdBy: adminUser._id,
      },
      {
        title: "Project-level authorization middleware",
        task: task2._id,
        isCompleted: true,
        createdBy: adminUser._id,
      },
      {
        title: "Role isolation integration tests",
        task: task2._id,
        isCompleted: false,
        createdBy: adminUser._id,
      },
    ]);

    // 6. Create Demo Notes
    console.log("Creating demo notes...");
    await ProjectNote.create([
      {
        title: "Sprint Kickoff Notes",
        content: "All milestones are on track for Q4 release. Security audits and CI checks are active.",
        category: "Milestones",
        project: project._id,
        createdBy: adminUser._id,
      },
      {
        title: "Design System Guidelines",
        content: "Tailwind CSS v4 components align with shadcn/ui patterns and accessible contrast.",
        category: "Design",
        project: project._id,
        createdBy: memberUser._id,
      },
    ]);

    // 7. Create Demo Activities
    console.log("Creating demo activities...");
    await Activity.create([
      {
        project: project._id,
        actor: adminUser._id,
        actionType: ActivityActionEnum.PROJECT_CREATED,
        resourceType: ActivityResourceEnum.PROJECT,
        resourceId: project._id,
        summary: `Created project "${project.name}"`,
        metadata: { status: project.status },
        createdAt: new Date(now - 3 * day),
      },
      {
        project: project._id,
        actor: adminUser._id,
        actionType: ActivityActionEnum.MEMBER_ADDED,
        resourceType: ActivityResourceEnum.MEMBER,
        resourceId: memberUser._id,
        summary: `Added ${memberUser.email} as member`,
        metadata: { email: memberUser.email, role: "member" },
        createdAt: new Date(now - 2 * day),
      },
      {
        project: project._id,
        actor: adminUser._id,
        actionType: ActivityActionEnum.TASK_CREATED,
        resourceType: ActivityResourceEnum.TASK,
        resourceId: task1._id,
        summary: `Created task "${task1.title}"`,
        metadata: { status: task1.status, priority: task1.priority },
        createdAt: new Date(now - 1 * day),
      },
      {
        project: project._id,
        actor: adminUser._id,
        actionType: ActivityActionEnum.TASK_STATUS_CHANGED,
        resourceType: ActivityResourceEnum.TASK,
        resourceId: task1._id,
        summary: `Changed status of task "${task1.title}" to done`,
        metadata: { status: "done", previousStatus: "in_progress" },
        createdAt: new Date(now - 12 * 60 * 60 * 1000),
      },
      {
        project: project._id,
        actor: memberUser._id,
        actionType: ActivityActionEnum.NOTE_CREATED,
        resourceType: ActivityResourceEnum.NOTE,
        resourceId: project._id,
        summary: `Created note "Design System Guidelines"`,
        metadata: { category: "Design" },
        createdAt: new Date(now - 2 * 60 * 60 * 1000),
      },
    ]);

    console.log("\n========================================================");
    console.log("Demo seed data created successfully!");
    console.log("========================================================");
    console.log("Demo Accounts Available:");
    console.log("  1. Admin Account:  admin@example.com  / Password123!");
    console.log("  2. Member Account: member@example.com / Password123!");
    console.log("Project: 'Alpha Platform Launch'");
    console.log("Tasks: 3 created (1 Done, 1 In Progress, 1 Todo)");
    console.log("Subtasks: 4 created");
    console.log("Notes: 2 created");
    console.log("Activities: 5 created in Project Timeline");
    console.log("========================================================\n");
  } catch (error) {
    console.error("Seeding failed:", error);
    process.exitCode = 1;
  } finally {
    await mongooseInstance.disconnect();
    console.log("Database connection closed.");
  }
}

seed();

