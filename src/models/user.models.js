import bcrypt from "bcrypt";
import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// User account data and authentication-related tokens.
const userSchema = new Schema(
  {
    avatar: {
      // Store both the public URL and the local file path for the avatar.
      type: {
        url: String,
        localPath: String,
      },
      default: {
        url: "https://placehold.co/200x200/EEE/31343C",
        localPath: "",
      },
    },
    username: {
      // Usernames are normalized before being stored and must be unique.
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    email: {
      // Emails are normalized before being stored and must be unique.
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      // Store only the bcrypt hash, never the plain-text password.
      type: String,
      required: [true, "password is required"],
    },
    fullName: {
      type: String,
      trim: true,
    },
    isEmailVerified: {
      // Set to true after the user completes email verification.
      type: Boolean,
      default: false,
    },
    refreshToken: {
      // Current refresh token saved for the user's session.
      type: String,
    },
    forgotPasswordToken: {
      // Hashed token used to authorize a password reset.
      type: String,
    },

    forgotPasswordExpiry: {
      // Time after which the password-reset token is invalid.
      type: Date,
    },
    emailVerificationToken: {
      // Hashed token used to verify the user's email address.
      type: String,
    },
    emailVerificationExpiry: {
      // Time after which the email-verification token is invalid.
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);
// Hash password before saving user to database
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();   // agr password modify nhi hui to next() call krdo and ye isModified() function mongoose ka function hai jo check krta hai ki password modify hua hai ya nhi agr password modify nhi hua to next() call krdo and ye next() function kaam krta hai ki ye next middleware ko call krta hai. agr password modify hua to next() call nhi hoga and password ko hash krke save karega.password modify sirf 2 cse mein hota hai. 1. jab user create hota hai 2. jab user password change krta hai. agr user update krta hai aur password change nhi krta to password ko hash krne ki zarurat nhi hai. isliye hum isModified() function ka use krte hain.
  this.password = await bcrypt.hash(this.password, 10); // Hash the password with a salt round of 10
  next();
});
// Compare a supplied plain-text password with the stored bcrypt hash.
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Create a short-lived token used to authenticate API requests.
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

// Create a longer-lived token used to obtain a new access token.
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  );
};

// Create a temporary token pair for email verification or password reset.
userSchema.methods.generateTemporaryToken = function () {
  // Return the plain token to the user, but store only its hash in the database.
  const unHashedToken = crypto.randomBytes(20).toString("hex");

  const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex");

  const tokenExpiry = Date.now() + 20 * 60 * 1000; // Token expires in 20 minutes.
  return { unHashedToken, hashedToken, tokenExpiry };
};

export const User = mongoose.model("User", userSchema);
