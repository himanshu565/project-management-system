import { Router } from "express";
import {
  getTasks,
  getTaskById,
  createTask,
  updateTask,
  deleteTask,
  createSubTask,
  updateSubTask,
  deleteSubTask,
} from "../controllers/task.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
  createTaskValidator,
  updateTaskValidator,
  createSubtaskValidator,
  updateSubtaskValidator,
} from "../validators/index.js";
import {
  verifyJWT,
  validateProjectPermission,
} from "../middlewares/auth.middleware.js";
import { upload } from "../middlewares/multer.middleware.js";
import { AvailableUserRole, UserRolesEnum } from "../utils/constants.js";

const router = Router();
router.use(verifyJWT);

const canManageTasks = [UserRolesEnum.ADMIN, UserRolesEnum.PROJECT_ADMIN];

router
  .route("/:projectId")
  .get(validateProjectPermission(AvailableUserRole), getTasks)
  .post(
    validateProjectPermission(canManageTasks),
    upload.array("attachments", 10),
    createTaskValidator(),
    validate,
    createTask
  );

router
  .route("/:projectId/t/:taskId")
  .get(validateProjectPermission(AvailableUserRole), getTaskById)
  .put(
    validateProjectPermission(canManageTasks),
    upload.array("attachments", 10),
    updateTaskValidator(),
    validate,
    updateTask
  )
  .delete(validateProjectPermission(canManageTasks), deleteTask);

router
  .route("/:projectId/t/:taskId/subtasks")
  .post(
    validateProjectPermission(canManageTasks),
    createSubtaskValidator(),
    validate,
    createSubTask
  );

router
  .route("/:projectId/st/:subTaskId")
  .put(
    validateProjectPermission(AvailableUserRole),
    updateSubtaskValidator(),
    validate,
    updateSubTask
  )
  .delete(validateProjectPermission(canManageTasks), deleteSubTask);

export default router;
