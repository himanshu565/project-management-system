import { User } from "../models/user.models.js";
import { ApiResponse } from "../utils/Api-Response.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import { EmailverificationMailgenCContent, sendEmail } from "../utils/mail.js";
import jwt from "jsonwebtoken";
import { json } from "express";

const generateAcessTokenandrefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const refreshtoken = user.generateRefreshToken();
    const accessToken = user.generateAccessToken();

    user.refreshToken = refreshtoken;
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

const login = asyncHandler(async (req, res) => {
  const { email, password, username } = req.body;

  if (!email) {
    throw new ApiError(400, "email is required ");
  }

  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(400, "user does not exists");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(400, "invalid credentials");
  }
  const { refreshtoken, accessToken } =
    await generateAcessTokenandrefreshTokens(user._id);

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );
  //cookies require options
  const options = {
    httponly: true,
    secure: true,
  };
  //now options are ready now send the response
  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshtoken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshtoken,
        },
        "user is logged in successfully"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: "",
      },
    },
    {
      new: true,
    }
  );
  const options = {
    httponly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "user logged out "));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "current user fetched successfully"));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;
  if (!verificationToken) {
    throw new ApiError(400, "Email verification token is missing");
  }
  let hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");
  const user = User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });
  if (!user) {
    throw new ApiError(400, "invalid or expired email verification token");
  } //if this is true user is valid

  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;
  user.isEmailVerified = true;
  await user.save({
    validateBeforeSave: false,
  });
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { isEmailVerified: user.isEmailVerified },
        "email verified successfully"
      )
    );
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user?._id);
  if (!user) {
    throw new ApiError(404, "user does not exits ");
  }
  if (user.isEmailVerified) {
    throw new ApiError(404, " email is already verified");
  } // it means email is not verified then we have to repeat the process
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
  //everything is done by our side now send the response or return
  return res
    .statu(200)
    .json(new ApiResponse(200, {}, "email sent ot your email"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.body.refreshToken || req.cookies.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "unauthorized user ");
  } // if its true we know that we have id in the refreshToken so we need to access it
  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(400, "Invalid refresh Token");
    }
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(400, "refresh token is expired ");
    }
    const options = {
      httponly: true,
      secure: true,
    };
    const { accessToken, refreshtoken: newRefreshToken } =
      await generateAcessTokenandrefreshTokens(user._id); //dont forget to update the refresh token in the databse
    user.refreshToken = newRefreshToken;
    user.save();
    return res
      .statu(200)
      .cookie("accessToke", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(400, " invalid refresh token ");
  }
});
export {
  login,
  registerUser,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
};
