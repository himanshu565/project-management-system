import { Task } from "../models/task.models.js";
import { Subtask } from "../models/subtask.models.js";
import { ApiResponse } from "../utils/Api-Response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";

const getTasks = asyncHandler(async (req, res) => {
  const { projectId } = req.params;

  const tasks = await Task.find({ project: projectId })
    .populate("assignedTo", "username avatar")
    .populate("assignedBy", "username avatar");

  return res
    .status(200)
    .json(new ApiResponse(200, tasks, "Tasks fetched successfully"));
});

const getTaskById = asyncHandler(async (req, res) => {
  const { taskId } = req.params;

  const task = await Task.findById(taskId)
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
  const { title, description, assignedTo, status } = req.body;

  const attachments = (req.files || []).map((file) => ({
    url: `${req.protocol}://${req.get("host")}/images/${file.filename}`,
    mimetype: file.mimetype,
    size: file.size,
  }));

  const task = await Task.create({
    title,
    description,
    project: projectId,
    assignedTo: assignedTo || undefined,
    assignedBy: req.user._id,
    status,
    attachments,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, task, "Task created successfully"));
});

const updateTask = asyncHandler(async (req, res) => {
  const { taskId } = req.params;
  const { title, description, assignedTo, status } = req.body;

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
  if (attachments.length > 0) update.$push = { attachments: { $each: attachments } };

  const { $push, ...setFields } = update;
  const task = await Task.findByIdAndUpdate(
    taskId,
    { $set: setFields, ...($push ? { $push } : {}) },
    { new: true, runValidators: true }
  );

  if (!task) {
    throw new ApiError(404, "Task not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, task, "Task updated successfully"));
});

const deleteTask = asyncHandler(async (req, res) => {
  const { taskId } = req.params;

  const task = await Task.findByIdAndDelete(taskId);
  if (!task) {
    throw new ApiError(404, "Task not found");
  }

  await Subtask.deleteMany({ task: taskId });

  return res
    .status(200)
    .json(new ApiResponse(200, task, "Task deleted successfully"));
});

const createSubTask = asyncHandler(async (req, res) => {
  const { taskId } = req.params;
  const { title } = req.body;

  const task = await Task.findById(taskId);
  if (!task) {
    throw new ApiError(404, "Task not found");
  }

  const subtask = await Subtask.create({
    title,
    task: taskId,
    createdBy: req.user._id,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, subtask, "Subtask created successfully"));
});

const updateSubTask = asyncHandler(async (req, res) => {
  const { subTaskId } = req.params;
  const { title, isCompleted } = req.body;

  const update = {};
  if (title !== undefined) update.title = title;
  if (isCompleted !== undefined) update.isCompleted = isCompleted;

  const subtask = await Subtask.findByIdAndUpdate(
    subTaskId,
    { $set: update },
    { new: true, runValidators: true }
  );

  if (!subtask) {
    throw new ApiError(404, "Subtask not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, subtask, "Subtask updated successfully"));
});

const deleteSubTask = asyncHandler(async (req, res) => {
  const { subTaskId } = req.params;

  const subtask = await Subtask.findByIdAndDelete(subTaskId);
  if (!subtask) {
    throw new ApiError(404, "Subtask not found");
  }

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
