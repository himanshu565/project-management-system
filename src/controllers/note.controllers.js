import { ProjectNote } from "../models/note.models.js";
import { ApiResponse } from "../utils/Api-Response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";

const getNotes = asyncHandler(async (req, res) => {
  const { projectId } = req.params;

  const notes = await ProjectNote.find({ project: projectId }).populate(
    "createdBy",
    "username avatar"
  );

  return res
    .status(200)
    .json(new ApiResponse(200, notes, "Notes fetched successfully"));
});

const getNoteById = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { noteId } = req.params;

  const note = await ProjectNote.findOne({ _id: noteId, project: projectId }).populate(
    "createdBy",
    "username avatar"
  );

  if (!note) {
    throw new ApiError(404, "Note not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, note, "Note fetched successfully"));
});

const createNote = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { title, content, category } = req.body;

  const note = await ProjectNote.create({
    project: projectId,
    title,
    content,
    category,
    createdBy: req.user._id,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, note, "Note created successfully"));
});

const updateNote = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { noteId } = req.params;
  const { title, content, category } = req.body;

  const update = { title, content, category };

  const note = await ProjectNote.findOneAndUpdate(
    { _id: noteId, project: projectId },
    { $set: update },
    { new: true, runValidators: true }
  );

  if (!note) {
    throw new ApiError(404, "Note not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, note, "Note updated successfully"));
});

const deleteNote = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { noteId } = req.params;

  const note = await ProjectNote.findOneAndDelete({ _id: noteId, project: projectId });
  if (!note) {
    throw new ApiError(404, "Note not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, note, "Note deleted successfully"));
});

export { getNotes, getNoteById, createNote, updateNote, deleteNote };
