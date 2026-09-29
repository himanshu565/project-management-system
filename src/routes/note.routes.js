import { Router } from "express";
import {
  getNotes,
  getNoteById,
  createNote,
  updateNote,
  deleteNote,
} from "../controllers/note.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { createNoteValidator } from "../validators/index.js";
import {
  verifyJWT,
  validateProjectPermission,
  validateObjectIdParam,
} from "../middlewares/auth.middleware.js";
import { AvailableUserRole, UserRolesEnum } from "../utils/constants.js";

const router = Router();
router.use(verifyJWT);

router
  .route("/:projectId")
  .get(validateProjectPermission(AvailableUserRole), getNotes)
  .post(
    validateProjectPermission([UserRolesEnum.ADMIN]),
    createNoteValidator(),
    validate,
    createNote
  );

router
  .route("/:projectId/:noteId")
  .get(
    validateProjectPermission(AvailableUserRole),
    validateObjectIdParam("noteId", "note"),
    getNoteById
  )
  .put(
    validateProjectPermission([UserRolesEnum.ADMIN]),
    validateObjectIdParam("noteId", "note"),
    createNoteValidator(),
    validate,
    updateNote
  )
  .delete(
    validateProjectPermission([UserRolesEnum.ADMIN]),
    validateObjectIdParam("noteId", "note"),
    deleteNote
  );

export default router;
