import mongoose, { Schema } from "mongoose";
import { AvailableActivityActions, AvailableActivityResources } from "../utils/constants.js";

const activitySchema = new Schema(
  {
    project: {
      type: Schema.Types.ObjectId,
      ref: "Project",
      required: true,
      index: true,
    },
    actor: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    actionType: {
      type: String,
      required: true,
      enum: AvailableActivityActions,
      index: true,
    },
    resourceType: {
      type: String,
      enum: AvailableActivityResources,
      required: true,
    },
    resourceId: {
      type: Schema.Types.ObjectId,
    },
    summary: {
      type: String,
      required: true,
      trim: true,
      maxlength: 300,
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: {},
    },
  },
  { timestamps: true }
);

// Compound index for fast paginated timelines ordered by newest first
activitySchema.index({ project: 1, createdAt: -1 });

export const Activity = mongoose.model("Activity", activitySchema);

