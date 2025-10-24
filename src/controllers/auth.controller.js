import { User } from "../models/user.models.js";
import { ApiResponse } from "../utils/Api-Response.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import { EmailverificationMailgenCContent, sendEmail } from "../utils/mail.js";
import jwt from "jsonwebtoken";
import { json } from "express";

/*
High-level overview
- This controller contains auth-related handlers (register, login, logout, token refresh,
  email verification, password reset, change password).
- Uses the User model for DB interactions and user instance methods to generate tokens
  and validate passwords.
- Responses use ApiResponse wrapper; errors are thrown as ApiError (handled by error middleware).
- asyncHandler wraps each async function to avoid repetitive try/catch in each route.
- Tokens:
  - Access token: short-lived JWT used for auth (returned and also set in cookie "accessToken").
  - Refresh token: long-lived JWT stored in DB (user.refreshToken) and cookie "refreshToken".
  - Temporary tokens: randomly generated (unHashedToken returned) then hashed and saved on user.
    Used for email verification and password reset flows.
Security notes:
- Cookies are set with options; ensure secure/httponly flags are correct for your environment.
- Temporary tokens are stored hashed in DB to prevent token leakage if DB is compromised.
- Many small typos in cookie names and method names exist (see inline TODOs) — watch for them.
*/
const generateAcessTokenandrefreshTokens = async (userId) => {
    /*
  Purpose:
  - Generate both access and refresh tokens for the given user id,
    persist refreshToken in DB and return both tokens.

  Implementation notes:
  - We rely on instance methods defined in User schema: generateRefreshToken() and generateAccessToken()
    which create signed JWTs using environment secrets.
  - After generating, set user.refreshToken and save with validateBeforeSave: false so pre-save validators
    for unrelated fields don't block this quick update.
  - Return both tokens to the caller so they can be sent in response or used otherwise.

  Error handling:
  - If anything fails we throw ApiError(500) so the global error handler returns a 500 to client.
  */
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
  /*
  Flow:
  1. Extract username, email, password, and role (role optional in current code).
  2. Check for existing user by username OR email. If found => 409 conflict.
  3. Create new User. User model should hash password in pre-save middleware.
  4. Generate a temporary token (unHashedToken + hashedToken + expiry) via user.generateTemporaryToken()
     - unHashedToken: sent to user via email (the clickable value)
     - hashedToken: stored in DB (so we never store the raw token)
  5. Save the hashed token and expiry on user and send verification email with URL:
     `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
  6. Return sanitized createdUser (exclude sensitive fields) and message.

  Important:
  - user.generateTemporaryToken() should be implemented in User model. It typically:
    - generates a random token (crypto.randomBytes)
    - creates a hashed version (sha256)
    - sets expiry (Date.now() + ttl)
    - returns both hashed and unhashed along with expiry
  - We send the unhashed token in email so user can click the link. On verify we hash the incoming token and match it to DB.
  - We exclude password, refreshToken, emailVerificationToken, emailVerificationExpiry before returning the user.
  */
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
    /*
  Flow:
  1. Validate email presence (login requires email).
  2. Fetch user by email. If not found -> error.
  3. Check password with user.isPasswordCorrect (should be implemented in model and compare hashed password).
  4. Generate tokens via generateAcessTokenandrefreshTokens -> store refreshToken in DB and return accessToken & refreshtoken.
  5. Return cookies and body with sanitized user and tokens.

  Cookie notes:
  - options: { httponly: true, secure: true } — these should probably be httpOnly (camelCase) and you may want to
    set sameSite depending on frontend. When developing locally over HTTP, secure: true will prevent cookies from being set;
    consider toggling secure based on NODE_ENV.
  - Cookies set here are convenience; your client can also read the access token from response body.
  */
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
    /*
  Flow:
  - Clear the refreshToken stored in DB for the current user (invalidate server-side).
  - Clear cookies on client (accessToken & refreshToken).
  - Return success.

  Note:
  - This is not sufficient if you issue long-lived tokens without server-side revocation for access tokens.
    Access token invalidation requires token blacklist or short token TTL with refresh flow.
  */
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
    /*
  - Simply returns req.user (populated by an auth middleware that validates the access token).
  - Depends on middleware earlier in the chain to attach user to req.
  */
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "current user fetched successfully"));
});

const verifyEmail = asyncHandler(async (req, res) => {
    /*
  Flow:
  - Accepts verificationToken from route params (this is the unhashed token that was emailed).
  - Hash it using sha256 and look up user by emailVerificationToken and expiry > now.
  - If user found: clear token + expiry and set isEmailVerified = true and save.
  - Return success.

  Important details:
  - We hash incoming token and compare to stored hashed value to avoid storing raw tokens in DB.
  - If you ever change hash algorithm or token generation details, make sure model and this logic align.
  - There is a line here that chains from `crypto.createHash` — the code uses `let hashedToken = crypto`
    followed by chained calls on next lines. This works but can look odd; it's just chaining off the crypto object.
  - TODOs/typos:
    - This function uses User.findOne but does not await it in current file — ensure it's awaited (the original file has `const user = User.findOne({ ... })`).
      Without await, user will be a Query object and the subsequent checks won't work. You should `await User.findOne(...)`.
    - Keep an eye out for these subtle bugs when reading later.
  */
  const { verificationToken } = req.params;
  if (!verificationToken) {
    throw new ApiError(400, "Email verification token is missing");
  }
  let hashedToken = crypto   //this is an unhashed token thats why we need to hash it
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
    /*
  Flow:
  - Ensure user exists (from req.user) and is not already verified.
  - Generate a new temporary token, save hashed token & expiry, send email with unhashed token link.
  - Return response.

  Note:
  - Double-check the response uses .status (original file used .statu in one place — that is a bug).
  - Make sure the User model's generateTemporaryToken() handles token TTL appropriately.
  */
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
    /*
  Flow:
  - Get incoming refresh token from body or cookies.
  - Verify the JWT using REFRESH_TOKEN_SECRET.
  - Find user by id embedded in decoded token.
  - Compare incoming refresh token string with user.refreshToken in DB (protects against token reuse if DB was rotated).
  - Generate new access token and new refresh token pair and save them on user.
  - Return new tokens and set cookies.

  Important security notes:
  - Verify the token signature using jwt.verify; catch errors to avoid leaking stack traces.
  - Compare the token string to user.refreshToken to guard against stolen-but-revoked tokens.
  - When issuing a new refresh token, persist it in DB to rotate tokens.
  - Cookie names and `options` casing matter.
    - The file contains several typos here:
      - .statu(200) -> should be .status(200)
      - .cookie("accessToke", ...) -> should be "accessToken"
      - options uses httponly instead of httpOnly (express expects httpOnly)
    - These typos will cause bugs: cookies not set, wrong status code, etc.

  Example correct cookie options in production:
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    // maxAge: ms(...)
  }
  */
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

const forgotPasswordRequest = asyncHandler(async (req, res) => {
  /*
  Flow:
  - User requests password reset by providing email.
  - If user exists:
    - Generate temporary token and store hashed version as forgotPasswordToken (note: file currently uses emailVerificationToken field for this — ensure your model supports both or you adjust).
    - Send email with reset link using FORGOT_PASSWORD_REDIRECT_URL + unHashedToken.
  - Return a generic success message so attackers cannot enumerate emails.

  Notes:
  - It's common to use separate fields like forgotPasswordToken and forgotPasswordExpiry.
  - Avoid returning whether an email exists or not to the caller. This code currently returns 404 if user not found — consider returning 200 always to avoid user enumeration.
  */
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "user does not exists", []);
  }
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  await sendEmail({
    to: user?.email,
    subject: "reset your password",
    mailgencontent: ForgotPasswordMailgenContent(
      user.username,
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}` // here we can use this or can create our won url just like we didi in register user
    ),
  });
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "password reset email has been sent to your email"
      )
    );
});

const resetForgotPassword = asyncHandler(async (req, res) => {
    /*
  Flow:
  - Accept resetToken param (unhashed), hash it, find user by forgotPasswordToken and expiry.
  - If valid: clear token fields, set new password (pre-save hook should hash it), save.
  - Return success.

  Notes:
  - The code hashes resetToken with sha256 — this must match how generateTemporaryToken hashed it.
  - Ensure the DB fields used here (forgotPasswordToken, forgotPasswordExpiry) match the ones set during forgotPasswordRequest.
  */
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  // we had unhashed token thats why we need to hash it
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });
  if (!user) {
    throw new ApiError(400, "invalid or expired password reset token");
  }

  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;

  user.password = newPassword; // as soon as i am touching my password my prehook will  be invoked and password will be hashed
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "password has been reset successfully"));
});

// this change password is for the user that is already logged in .
const changeCurrentPassword = asyncHandler(async (req, res) => {
    /*
  Flow:
  - User is logged in (req.user present). Provide oldPassword and newPassword.
  - Validate oldPassword using user.isPasswordCorrect.
  - If valid, set new password and save (pre-save should hash).
  - Return success.

  Notes:
  - Always validate old password to prevent account takeover via a stolen cookie.
  - Consider requiring password strength checks on newPassword.
  */
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user?._id);

  const isPasswordValid = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordValid) {
    throw new ApiError(400, "old password is invalid");
  }
  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed succesfully"));
});
export {
  login,
  registerUser,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordRequest,
  changeCurrentPassword,
  resetForgotPassword,
};
