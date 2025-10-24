import multer from "multer";

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, `./public/images`);
  },
  /** Specifies the folder where uploaded files should be saved.

cb (callback) takes two arguments:

null (no error)

'./public/images' (path to store files)

*/

  filename: function (req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`); //Controls the file name of the saved file, file.originalname is the original file name (like "photo.png") So, if you upload photo.png, it might be saved as: 1690481234567-photo.png
  },
});

export const upload = multer({
  storage,
  limits: {
    fileSize: 1 * 1000 * 1000,
  },
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
