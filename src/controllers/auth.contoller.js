import { User } from "../models/user.models.js";
import { ApiResponse } from "../utils/Api-Response.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "next/dist/server/api-utils/index.js";
import { EmailverificationMailgenCContent, sendEmail } from "../utils/mail.js";

const generateAcessTokenandrefreshTokens = async (userId) => {
  try {
    const user = User.findById(userId);
    const refreshtoken = user.generateRefreshToken();
    const accessToken = user.generateAccessToken();
    user.refreshtoken = refreshtoken;
    await user.save({ validateBeforeSave: false });
    //this save method is used to save the user without validating the other fields and it also generates the refresh token in the db
    return { accessToken, refreshtoken };
  } catch (error) {
    throw new ApiError(500, "something went wrong while generating token", []);
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password, role } = req.body;

  const exitedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  if (exitedUser) {
    throw new ApiError(409, "username or email already exists", []);
  }
  const user = await User.create({
    username,
    email,
    password,
    isEmailVerified: false,
  });

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  await sendEmail({
    to: user?.email,
    subject: "verify your email",
    mailgencontent: EmailverificationMailgenCContent(
      user.username,
      `${req.protocol}://${req.get(
        "host"
      )}/api/v1/users/verify-email/${unHashedToken}`
    ),
  });
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );
  if (!createdUser) {
    throw new ApiError(500, "something went wrong while registering a user");
  }
  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        "user registered successfully and verification email has been sent on your email"
      )
    );
});
export { registerUser };
