import { body } from "express-validator";
import {
  AvailableUserRole,
  AvailableTaskStatus,
  AvailableProjectStatus,
  AvailableTaskPriority,
} from "../utils/constants.js";

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("email is requred")
      .isEmail()
      .withMessage("Email is not valid"),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("username is required")
      .isLowercase()
      .withMessage("username must be in lowercase")
      .isLength({ min: 3 })
      .withMessage("username must be of atleast 3 character long "),

    body("password").trim().notEmpty().withMessage("password cannot be empty"),

    body("fullname").trim().optional(),
  ];
};

const userLoginValidator = () => {
  return [
    body("email").trim().optional().isEmail().withMessage("email is not valid"),
    body("password").trim().notEmpty().withMessage("password cannot be empty"),
  ]
};

const userChangeCurrentPasswordValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("old password is required"),
    body("newPassword").notEmpty().withMessage("new password is required"),
  ];
};
const userForgotPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is not valid"),
  ];
};
const userResetForgotPasswordValidator = () => {
  return [
    body("newPassword").notEmpty().withMessage("new password is required"),
  ];
};
const createProjectValidator = () => {
  return [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("description").optional({ values: "falsy" }).trim(),
    body("status").optional({ values: "falsy" }).isIn(AvailableProjectStatus).withMessage("Status is invalid"),
    body("startDate").optional({ values: "falsy" }).isISO8601().withMessage("Start date is invalid"),
    body("endDate")
      .optional({ values: "falsy" })
      .isISO8601()
      .withMessage("End date is invalid")
      .custom((endDate, { req }) => {
        if (req.body?.startDate && endDate && new Date(endDate) < new Date(req.body.startDate)) {
          throw new Error("End date cannot be earlier than start date");
        }
        return true;
      }),
  ];
};

const updateProjectValidator = () => {
  return [
    body("name").optional().trim().notEmpty().withMessage("Name cannot be empty"),
    body("description").optional().trim(),
    body("status").optional({ values: "falsy" }).isIn(AvailableProjectStatus).withMessage("Status is invalid"),
    body("startDate").optional({ values: "falsy" }).isISO8601().withMessage("Start date is invalid"),
    body("endDate")
      .optional({ values: "falsy" })
      .isISO8601()
      .withMessage("End date is invalid")
      .custom((endDate, { req }) => {
        if (req.body?.startDate && endDate && new Date(endDate) < new Date(req.body.startDate)) {
          throw new Error("End date cannot be earlier than start date");
        }
        return true;
      }),
  ];
};

const addMembertoProjectValidator = () => {
  return [
    body("email")
      .trim()
      .normalizeEmail()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
    body("role")
      .notEmpty()
      .withMessage("Role is required")
      .trim()
      .customSanitizer((value) =>
        value
          .replace(/([a-z])([A-Z])/g, "$1_$2")
          .toLowerCase()
          .replace(/[\s-]+/g, "_")
      )
      .isIn(AvailableUserRole)
      .withMessage("Role is invalid"),
  ];
};

const createTaskValidator = () => {
  return [
    body("title").trim().notEmpty().withMessage("Title is required"),
    body("description").optional(),
    body("status")
      .optional()
      .isIn(AvailableTaskStatus)
      .withMessage("Status is invalid"),
    body("dueDate")
      .optional({ values: "falsy" })
      .isISO8601()
      .withMessage("Due date must be a valid ISO 8601 date"),
    body("priority")
      .optional({ values: "falsy" })
      .isIn(AvailableTaskPriority)
      .withMessage("Priority is invalid"),
    body("assignedTo").optional().isMongoId().withMessage("assignedTo must be a valid user id"),
  ];
};

const updateTaskValidator = () => {
  return [
    body("title").optional().trim().notEmpty().withMessage("Title cannot be empty"),
    body("description").optional(),
    body("assignedTo").optional().isMongoId().withMessage("assignedTo must be a valid user id"),
    body("status")
      .optional()
      .isIn(AvailableTaskStatus)
      .withMessage("Status is invalid"),
    body("dueDate")
      .optional({ values: "falsy" })
      .isISO8601()
      .withMessage("Due date must be a valid ISO 8601 date"),
    body("priority")
      .optional({ values: "falsy" })
      .isIn(AvailableTaskPriority)
      .withMessage("Priority is invalid"),
  ];
};

const createSubtaskValidator = () => {
  return [body("title").trim().notEmpty().withMessage("Title is required")];
};

const updateSubtaskValidator = () => {
  return [
    body("title").optional().trim().notEmpty().withMessage("Title cannot be empty"),
    body("isCompleted").optional().isBoolean().withMessage("isCompleted must be a boolean"),
  ];
};

const createNoteValidator = () => {
  return [
    body("title").optional().trim(),
    body("content").trim().notEmpty().withMessage("Content is required"),
    body("category").optional().trim(),
  ];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userResetForgotPasswordValidator,
  userForgotPasswordValidator,
  userChangeCurrentPasswordValidator,
  addMembertoProjectValidator,
  createProjectValidator,
  updateProjectValidator,
  createTaskValidator,
  updateTaskValidator,
  createSubtaskValidator,
  updateSubtaskValidator,
  createNoteValidator,
};
