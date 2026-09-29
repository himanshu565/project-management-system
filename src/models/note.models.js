import mongoose, { Schema } from "mongoose";

const projectNoteSchema = new Schema(
  {
    title: {
      type: String,
      trim: true,
    },
    project: {
      type: Schema.Types.ObjectId,
      ref: "Project",
      required: true,
    },
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    content: {
      type: String,
      required: true,
      trim: true,
    },
    category: {
      type: String,
      trim: true,
    },
  },
  { timestamps: true },
);

export const ProjectNote = mongoose.model("ProjectNote", projectNoteSchema);
