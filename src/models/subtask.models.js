import mongoose, { Schema } from "mongoose";

const subTaskSchema = new Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    task: {
      type: Schema.Types.ObjectId, // Schema.Types.ObjectId  => Tells Mongoose to store a MongoDB ObjectId 
      ref: "Task",
      required: true,
    },
    isCompleted: {
      type: Boolean,
      default: false,
    },
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: "User",    //The ref: 'User' tells Mongoose that this ObjectId refers to a document in the User collection.
      required: true,
    },
  },
  { timestamps: true },
);

export const Subtask = mongoose.model("Subtask", subTaskSchema);
