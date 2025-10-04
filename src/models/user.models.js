import { string } from "astro:schema";
import bcrypt from "bcryptjs";
import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import crypto from "crypto";
const userSchema = new Schema(
  {
    avatar: {
      type: {
        url: string,
        localPath: string,
      },
      default: {
        url: "https://placehold.co/200x200/EEE/31343C",
        localPath: "",
      },
    },
    username: {
      type: string,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    email: {
      type: string,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: string,
      required: [true, "password is required"],
      unique: true,
      lowercase: true,
      trim: true,
    },
    fullName: {
      type: string,
      trim: true,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    refreshToken: {
      type: string,
    },
    forgotPasswordToken: {
      type: string,
    },
    forgotPasswordExpiry: {
      type: Date,
    },
    emailVerificationToken: {
      type: string,
    },
    emailVerificationExpiry: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);
// Hash password before saving user to database
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});
// Compare password method
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      username: this.username,
      email: this.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
};
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  );
};
userSchema.methods.generateTemporaryToken = function () {
  const unHashedToken  = crypto.randomBytes(20).toString("hex");

  const hashedToken = crypto
  .createHash("sha256")   //inside the createhash we write our algo for hashing we wanna use 
  .update(unHashedToken)
  .digest("hex")

  const tokenExpiry = Date.now() + (20*60*1000) //20 minutes
  return {unHashedToken ,hashedToken ,tokenExpiry}


};

export const User = mongoose.model("User", userSchema);
