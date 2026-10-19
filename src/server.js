import "dotenv/config";
import app from "./app.js";
import connectDB from "./db/index.js";
import { assertRequiredEnvironment } from "./utils/env-validator.js";

assertRequiredEnvironment();

const port = process.env.PORT || 8000;

connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("Failed to connect to DB", err);
    process.exit(1);
  });