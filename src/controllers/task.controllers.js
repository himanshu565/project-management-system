import { Task } from "../models/task.models.js";
import { Subtask } from "../models/subtask.models.js";
import { User } from "../models/user.models.js";
import { ProjectMember } from "../models/projectmember.models.js";
import { ApiResponse } from "../utils/Api-Response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { recordActivity } from "../utils/activity-logger.js";
import { ActivityActionEnum, ActivityResourceEnum } from "../utils/constants.js";

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const getTasks = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { search, status } = req.query;
  const filters = { project: projectId };

  if (status) {
    filters.status = status;
  }

  if (search?.trim()) {
    const searchPattern = escapeRegex(search.trim());
    filters.$or = [
      { title: { $regex: searchPattern, $options: "i" } },
      { description: { $regex: searchPattern, $options: "i" } },
    ];
  }

  const tasks = await Task.find(filters)
    .populate("assignedTo", "username avatar")
    .populate("assignedBy", "username avatar");

  return res
    .status(200)
    .json(new ApiResponse(200, tasks, "Tasks fetched successfully"));
});

const getTaskById = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { taskId } = req.params;

  const task = await Task.findOne({ _id: taskId, project: projectId })
    .populate("project", "name description status startDate endDate")
    .populate("assignedTo", "username avatar")
    .populate("assignedBy", "username avatar");

  if (!task) {
    throw new ApiError(404, "Task not found");
  }

  const subtasks = await Subtask.find({ task: taskId });

  return res
    .status(200)
    .json(new ApiResponse(200, { ...task.toObject(), subtasks }, "Task fetched successfully"));
});

const createTask = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { title, description, assignedTo, status, dueDate, priority } = req.body;

  const attachments = (req.files || []).map((file) => ({
    url: `${req.protocol}://${req.get("host")}/images/${file.filename}`,
    mimetype: file.mimetype,
    size: file.size,
  }));

  if (assignedTo) {
    const assignedMember = await ProjectMember.exists({
      user: assignedTo,
      project: projectId,
    });
    if (!assignedMember) {
      throw new ApiError(400, "Assigned user is not a member of this project");
    }

    const assignedUser = await User.exists({ _id: assignedTo });
    if (!assignedUser) {
      throw new ApiError(404, "Assigned user not found");
    }
  }

  const task = await Task.create({
    title,
    description,
    project: projectId,
    assignedTo: assignedTo || undefined,
    assignedBy: req.user._id,
    status,
    dueDate: dueDate ? new Date(dueDate) : undefined,
    priority: priority || undefined,
    attachments,
  });

  await recordActivity({
    project: projectId,
    actor: req.user._id,
    actionType: ActivityActionEnum.TASK_CREATED,
    resourceType: ActivityResourceEnum.TASK,
    resourceId: task._id,
    summary: `Created task "${task.title}"`,
    metadata: { status: task.status, priority: task.priority, dueDate: task.dueDate },
  });

  return res
    .status(201)
    .json(new ApiResponse(201, task, "Task created successfully"));
});

const updateTask = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { taskId } = req.params;
  const { title, description, assignedTo, status, dueDate, priority } = req.body;

  const attachments = (req.files || []).map((file) => ({
    url: `${req.protocol}://${req.get("host")}/images/${file.filename}`,
    mimetype: file.mimetype,
    size: file.size,
  }));

  const update = {};
  if (title !== undefined) update.title = title;
  if (description !== undefined) update.description = description;
  if (assignedTo !== undefined) update.assignedTo = assignedTo;
  if (status !== undefined) update.status = status;
  if (dueDate !== undefined) update.dueDate = dueDate ? new Date(dueDate) : null;
  if (priority !== undefined) update.priority = priority;
  if (attachments.length > 0) update.$push = { attachments: { $each: attachments } };

  const { $push, ...setFields } = update;
  if (assignedTo !== undefined) {
    const assignedMember = await ProjectMember.exists({
      user: assignedTo,
      project: projectId,
    });
    if (!assignedMember) {
      throw new ApiError(400, "Assigned user is not a member of this project");
    }

    const assignedUser = await User.exists({ _id: assignedTo });
    if (!assignedUser) {
      throw new ApiError(404, "Assigned user not found");
    }
  }

  const existingTask = await Task.findOne({ _id: taskId, project: projectId });
  if (!existingTask) {
    throw new ApiError(404, "Task not found");
  }

  const task = await Task.findOneAndUpdate(
    { _id: taskId, project: projectId },
    { $set: setFields, ...($push ? { $push } : {}) },
    { new: true, runValidators: true }
  );

  const isStatusChanged = status && status !== existingTask.status;
  const actionType = isStatusChanged
    ? ActivityActionEnum.TASK_STATUS_CHANGED
    : ActivityActionEnum.TASK_UPDATED;
  const summary = isStatusChanged
    ? `Changed status of task "${task.title}" to ${task.status}`
    : `Updated task "${task.title}"`;

  await recordActivity({
    project: projectId,
    actor: req.user._id,
    actionType,
    resourceType: ActivityResourceEnum.TASK,
    resourceId: task._id,
    summary,
    metadata: {
      status: task.status,
      priority: task.priority,
      previousStatus: existingTask.status,
    },
  });

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        await Task.findById(task._id)
          .populate("project", "name description status startDate endDate")
          .populate("assignedTo", "username avatar")
          .populate("assignedBy", "username avatar"),
        "Task updated successfully"
      )
    );
});

const deleteTask = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { taskId } = req.params;

  const task = await Task.findOneAndDelete({ _id: taskId, project: projectId });
  if (!task) {
    throw new ApiError(404, "Task not found");
  }

  await Subtask.deleteMany({ task: taskId });

  await recordActivity({
    project: projectId,
    actor: req.user._id,
    actionType: ActivityActionEnum.TASK_DELETED,
    resourceType: ActivityResourceEnum.TASK,
    resourceId: task._id,
    summary: `Deleted task "${task.title}"`,
  });

  return res
    .status(200)
    .json(new ApiResponse(200, task, "Task deleted successfully"));
});

const createSubTask = asyncHandler(async (req, res) => {
  const { taskId, projectId } = req.params;
  const { title } = req.body;

  const task = await Task.findOne({ _id: taskId, project: projectId });
  if (!task) {
    throw new ApiError(404, "Task not found");
  }

  const subtask = await Subtask.create({
    title,
    task: taskId,
    createdBy: req.user._id,
  });

  await recordActivity({
    project: projectId,
    actor: req.user._id,
    actionType: ActivityActionEnum.SUBTASK_CREATED,
    resourceType: ActivityResourceEnum.SUBTASK,
    resourceId: subtask._id,
    summary: `Added subtask "${subtask.title}" to task "${task.title}"`,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, subtask, "Subtask created successfully"));
});

const updateSubTask = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { subTaskId } = req.params;
  const { title, isCompleted } = req.body;

  const update = {};
  if (title !== undefined) update.title = title;
  if (isCompleted !== undefined) update.isCompleted = isCompleted;

  const existingSubtask = await Subtask.findById(subTaskId).select("task");
  if (!existingSubtask) {
    throw new ApiError(404, "Subtask not found");
  }

  const task = await Task.findOne({
    _id: existingSubtask.task,
    project: projectId,
  });
  if (!task) {
    throw new ApiError(404, "Subtask not found");
  }

  const subtask = await Subtask.findByIdAndUpdate(
    subTaskId,
    { $set: update },
    { new: true, runValidators: true }
  );

  if (!subtask) {
    throw new ApiError(404, "Subtask not found");
  }

  const summary =
    isCompleted !== undefined
      ? `${subtask.isCompleted ? "Completed" : "Reopened"} subtask "${subtask.title}"`
      : `Updated subtask "${subtask.title}"`;

  await recordActivity({
    project: projectId,
    actor: req.user._id,
    actionType: ActivityActionEnum.SUBTASK_STATUS_CHANGED,
    resourceType: ActivityResourceEnum.SUBTASK,
    resourceId: subtask._id,
    summary,
    metadata: { isCompleted: subtask.isCompleted },
  });

  return res
    .status(200)
    .json(new ApiResponse(200, subtask, "Subtask updated successfully"));
});

const deleteSubTask = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { subTaskId } = req.params;

  const existingSubtask = await Subtask.findById(subTaskId).select("task title");
  if (!existingSubtask) {
    throw new ApiError(404, "Subtask not found");
  }

  const task = await Task.exists({
    _id: existingSubtask.task,
    project: projectId,
  });
  if (!task) {
    throw new ApiError(404, "Subtask not found");
  }

  const subtask = await Subtask.findByIdAndDelete(subTaskId);
  if (!subtask) {
    throw new ApiError(404, "Subtask not found");
  }

  await recordActivity({
    project: projectId,
    actor: req.user._id,
    actionType: ActivityActionEnum.SUBTASK_DELETED,
    resourceType: ActivityResourceEnum.SUBTASK,
    resourceId: subtask._id,
    summary: `Deleted subtask "${subtask.title}"`,
  });

  return res
    .status(200)
    .json(new ApiResponse(200, subtask, "Subtask deleted successfully"));
});

export {
  getTasks,
  getTaskById,
  createTask,
  updateTask,
  deleteTask,
  createSubTask,
  updateSubTask,
  deleteSubTask,
};
