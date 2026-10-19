import multer from "multer";
import { ApiError } from "../utils/api-error.js";

export const allowedMimeTypes = [
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
  "application/pdf",
  "text/plain",
];

export const fileFilter = (req, file, cb) => {
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new ApiError(
        400,
        `Unsupported file type: ${file.mimetype}. Allowed types: JPEG, PNG, WEBP, GIF, PDF, TXT`
      ),
      false
    );
  }
};

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, `./public/images`);
  },
  filename: function (req, file, cb) {
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, `${Date.now()}-${sanitized}`);
  },
});

export const upload = multer({
  storage,
  limits: {
    fileSize: 1 * 1000 * 1000,
  },
  fileFilter,
});
/**
 * Multer — quick notes for future revision:
 *
 * - What is Multer?
 *   Multer is an Express middleware for handling multipart/form-data, which is primarily
 *   used for uploading files (images, documents, etc.) from HTML forms or API clients.
 *
 * - What this file configures:
 *   * storage: multer.diskStorage is used to persist uploaded files to disk.
 *     - destination: './public/images' (where uploaded files are saved)
 *     - filename: timestamp-prefixed original filename to reduce collisions
 *   * limits: fileSize set to 1 * 1000 * 1000 (1 MB) to prevent excessively large uploads
 *
 *   Multer needs to know where and how to store uploaded files.
 *   You define this using multer.diskStorage().
 *
 * - Typical usage in routes:
 *   router.post('/upload', upload.single('image'), controllerFunction)
 *   router.post('/photos', upload.array('photos', 5), controllerFunction)
 *
 * - Recommendations / reminders:
 *   * Validate file type (MIME / extension) in a fileFilter before saving to disk.
 *   * Ensure the './public/images' directory exists and is writable.
 *   * Sanitize filenames to avoid unexpected characters.
 *   * Handle upload errors (e.g., multer's LIMIT_FILE_SIZE) in your route error handling.
 *   * Consider storage alternatives (S3, Cloud Storage) for production or large-scale apps.
 */
