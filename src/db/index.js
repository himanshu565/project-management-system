import mongoose from "mongoose";

const connectDB = async () => {
  const uri = process.env.MONGO_URI || process.env.MONGODB_URI;
  if (!uri) {
    throw new Error(
      "MongoDB connection URI is missing. Set MONGO_URI or MONGODB_URI in your environment."
    );
  }

  try {
    const connectionInstance = await mongoose.connect(uri);
    console.log(
      `[DATABASE] MongoDB connected successfully! Host: ${connectionInstance.connection.host}`
    );
  } catch (error) {
    console.error("[DATABASE ERROR] Failed to connect to MongoDB:", error.message);
    throw error;
  }
};
export default connectDB;

