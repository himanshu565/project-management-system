import "dotenv/config";
import app from "./app.js";
import connectDB from "./db/index.js";

let dbConnected = false;

const handler = async (req, res) => {
  try {
    if (!dbConnected) {
      await connectDB();
      dbConnected = true;
    }

    return app(req, res);
  } catch (error) {
    console.error("Database connection failed:", error);
    return res.status(500).json({
      success: false,
      message: "Database connection failed",
    });
  }
};

export default handler;