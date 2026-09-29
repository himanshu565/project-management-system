import { body } from "express-validator";
import { AvailableUserRole, AvailableTaskStatus } from "../utils/constants.js";

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
    body("name").notEmpty().withMessage("Name is required"),
    body("description").optional(),
  ];
};

const updateProjectValidator = () => {
  return [
    body("name").optional().trim().notEmpty().withMessage("Name cannot be empty"),
    body("description").optional(),
  ];
};

const addMembertoProjectValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
    body("role")
      .notEmpty()
      .withMessage("Role is required")
      .isIn(AvailableUserRole)
      .withMessage("Role is invalid"),
  ];
};

const createTaskValidator = () => {
  return [
    body("title").trim().notEmpty().withMessage("Title is required"),
    body("description").optional(),
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
  return [body("content").trim().notEmpty().withMessage("Content is required")];
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
