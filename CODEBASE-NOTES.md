# Project Camp Backend - Codebase Notes

Yeh file project ke code ko samajhne ke liye banayi gayi hai. Isme bataya gaya hai ki humne kya code likha, uska purpose kya hai, aur woh code project ke kis file me use hota hai.

## 1. Project ka overall purpose

Yeh ek REST API backend hai jo project-management system ke liye banaya gaya hai. Iska purpose hai:

- users ko register aur login karwana;
- password aur email verification handle karna;
- projects create aur manage karna;
- projects me members add karna aur unke roles manage karna;
- tasks, subtasks aur notes ke liye data models provide karna;
- API ka health status check karna.

Main technologies:

- **Express:** HTTP server aur routes ke liye;
- **MongoDB + Mongoose:** database aur schemas ke liye;
- **JWT:** access aur refresh token authentication ke liye;
- **bcrypt:** passwords ko securely hash karne ke liye;
- **express-validator:** request data validate karne ke liye;
- **Multer:** file uploads ke liye;
- **Nodemailer + Mailgen:** verification aur password-reset emails ke liye.

## 2. Application start kaise hoti hai

### `src/index.js`

Yeh application ka entry point hai.

- `dotenv` `.env` file se environment variables load karta hai.
- `PORT` se server ka port milta hai; agar value na ho to `3000` use hota hai.
- `connectDB()` MongoDB se connection banata hai.
- Database connection successful hone ke baad `app.listen()` server start karta hai.

**Humne yeh kyu kiya:** Server ko database ready hone ke baad hi start karna chahiye. Isse application requests receive karne se pehle database dependency available hoti hai.

### `src/db/index.js`

- `mongoose.connect(process.env.MONGO_URI)` MongoDB connection banata hai.
- Connection error par error log hota hai aur process exit karta hai.

**Humne yeh kyu kiya:** Database connection ko alag function me rakhne se startup logic clean aur reusable rehta hai.

## 3. Express application configuration

### `src/app.js`

Yeh file Express application configure karti hai.

- `express.json()` JSON request body parse karta hai.
- `express.urlencoded()` form data parse karta hai.
- `express.static("public")` public files, jaise uploaded images, serve karta hai.
- `cookieParser()` cookies ko `req.cookies` me available karta hai.
- `CORS()` frontend ko backend ke saath communicate karne ki permission deta hai.
- Health, auth aur project routers ko API prefixes ke saath mount kiya gaya hai:
  - `/api/v1/healthcheck`
  - `/api/v1/auth`
  - `/api/v1/projects`
- `/` route basic server response return karta hai.

**Humne yeh kyu kiya:** Middleware common request processing ko centralize karta hai aur route prefixes API ko organized aur versionable banate hain.

### `src/controllers/healthcheck.js`

`healthcheck` controller `200` response ke saath API running status return karta hai. Response `ApiResponse` wrapper ke andar bheja jata hai aur `asyncHandler` asynchronous error handling provide karta hai.

**Humne yeh kyu kiya:** Monitoring tools ya frontend ek simple endpoint call karke check kar sakte hain ki backend available hai ya nahi.

### `src/routes/healtcheck.routes.js`

Yeh router `GET /` ko `healthcheck` controller se connect karta hai. `src/app.js` ise `/api/v1/healthcheck` prefix ke saath mount karta hai, isliye final endpoint hai:

`GET /api/v1/healthcheck/`

## 4. PRD ka role

### `PRD.md`

PRD project ki requirements aur expected behavior define karta hai. Isme yeh cheezein documented hain:

- target users: Admin, Project Admin aur Member;
- authentication, email verification aur password management;
- project aur team-member management;
- task, subtask aur project-note features;
- health-check endpoint;
- API endpoint structure;
- role-permission matrix;
- user roles aur task statuses;
- security, file-management aur success criteria.

**Humne yeh kyu kiya:** PRD coding se pehle project ka expected scope define karta hai. Isse controllers, routes, models aur permissions ko business requirements ke saath compare kiya ja sakta hai.

**Important difference:** PRD me task aur note ke complete endpoints listed hain, lekin current `src/app.js` me unke routers mounted nahi hain. Isliye PRD planned/required behavior batata hai, jabki actual implementation ka source code current routes aur controllers hain.

## 5. Authentication flow

### `src/models/user.models.js`

`User` schema user account aur authentication data define karta hai.

- `username`, `email` aur `password` user identity ke liye hain.
- `lowercase`, `trim` aur `unique` username/email ko normalize aur duplicate accounts ko prevent karne me help karte hain.
- `avatar` profile image ka URL aur local path store karta hai.
- `isEmailVerified` email verification ka status store karta hai.
- `refreshToken` active session ka refresh token store karta hai.
- `forgotPasswordToken` aur `emailVerificationToken` ke hashed values database me store hote hain.
- Token expiry fields token validity limit karte hain.

**Password hashing:** `pre("save")` middleware password modify hone par bcrypt hash banata hai. Agar password modify nahi hua, to dobara hash nahi hota.

**Humne yeh kyu kiya:** Plain-text password database me store karna unsafe hota hai. `isModified("password")` use karne se existing hash ko dobara hash karne ki problem nahi hoti.

**Model methods:**

- `isPasswordCorrect()` supplied password ko stored bcrypt hash se compare karta hai.
- `generateAccessToken()` short-lived JWT banata hai.
- `generateRefreshToken()` long-lived JWT banata hai.
- `generateTemporaryToken()` random raw token, uska SHA-256 hash aur 20-minute expiry return karta hai.

Raw temporary token email/link me bheja jata hai, lekin database me sirf hash store hota hai.

### `src/controllers/auth.controller.js`

Yeh authentication requests ka business flow handle karta hai.

- `registerUser`: duplicate user check, user creation, email-verification token generation aur verification email.
- `login`: user lookup, password comparison, access/refresh token generation aur cookies.
- `logoutUser`: database se refresh token clear karta hai aur cookies clear karta hai.
- `getCurrentUser`: authenticated user ka data return karta hai.
- `verifyEmail`: emailed token ko hash karke database token se match karta hai aur account verify karta hai.
- `resendEmailVerification`: unverified user ke liye naya verification token aur email banata hai.
- `refreshAccessToken`: refresh token verify karke naye tokens issue karta hai.
- Password reset/change handlers forgot-password aur change-password flow ke liye hain.

**Humne yeh kyu kiya:** Authentication logic ko controller me rakhne se routes sirf request mapping karte hain, jabki actual user/token workflow ek jagah maintain hota hai.

### `src/middlewares/auth.middleware.js`

#### `verifyJWT`

- Access token cookie ya `Authorization: Bearer <token>` header se read karta hai.
- JWT secret ke saath token verify karta hai.
- User ko database se load karta hai.
- Sensitive fields select se exclude karta hai.
- Valid user ko `req.user` par attach karta hai.

**Humne yeh kyu kiya:** Protected controllers ko har baar token parsing ka code repeat nahi karna padta.

#### `validateProjectPermission`

- `projectId` aur logged-in user ke basis par `ProjectMember` record find karta hai.
- User ka project role `req.user.role` me attach karta hai.
- Allowed roles me role na hone par `403` error deta hai.

**Humne yeh kyu kiya:** Project-level role-based access control ko reusable middleware me centralize kiya gaya hai.

## 6. Routes aur request validation

### `src/routes/auth.route.js`

Auth endpoints ko controller handlers aur middleware se connect karta hai.

- Public routes: register, login, email verification, refresh token, forgot/reset password.
- Protected routes: logout, current user, change password, resend verification.
- Protected routes par `verifyJWT` use hota hai.
- Body validation ke baad `validate` middleware run hota hai.

### `src/routes/project.routes.js`

- Router level par `verifyJWT` lagaya gaya hai, isliye project ke sabhi endpoints authenticated hain.
- Project list/create routes `/` par hain.
- Project details/update/delete routes `/:projectId` par hain.
- Member management routes `/:projectId/members` aur `/:projectId/members/:userId` par hain.
- Admin-only operations ke liye `validateProjectPermission([UserRolesEnum.ADMIN])` use hota hai.

### `src/validators/index.js`

Request body validation rules define karta hai:

- user registration/login;
- password change;
- forgot/reset password;
- project create/update;
- project member add;
- member role allowed roles me hai ya nahi.

**Humne yeh kyu kiya:** Invalid input ko database ya controller tak pahunchne se pehle reject karna API ko predictable aur secure banata hai.

### `src/middlewares/validator.middleware.js`

`validationResult(req)` previous express-validator rules ke results collect karta hai.

- Agar errors nahi hain, request `next()` ke through controller tak jati hai.
- Agar errors hain, unhe field aur message ke objects me convert kiya jata hai.
- Invalid request par `ApiError(422, ...)` throw hota hai.

**Humne yeh kyu kiya:** Validation logic ko controllers se alag rakhne se har endpoint ka input check reusable aur consistent rehta hai.

## 7. Project aur membership management

### `src/models/project.models.js`

Project ka `name`, `description` aur creator ka `createdBy` store karta hai. `createdBy` User model ko reference karta hai.

### `src/models/projectmember.models.js`

User aur Project ke beech membership relation store karta hai.

- `user`: member user ka reference;
- `project`: project ka reference;
- `role`: `admin`, `project_admin` ya `member`.

**Humne yeh kyu kiya:** Role ko User document me global rakhne ke bajay membership document me rakhne se ek user alag projects me alag roles rakh sakta hai.

### `src/controllers/project.controllers.js`

- `getProjects`: logged-in user ke projects aur member count aggregate karta hai.
- `getProjectById`: project details return karta hai.
- `createProject`: project banata hai aur creator ko admin member banata hai.
- `updateProject`: project name/description update karta hai.
- `deleteProject`: project delete karta hai.
- `addMembersToProject`: email se user find karke project membership create/update karta hai.
- `getProjectMembers`: project ke members ko user profile fields ke saath return karta hai.
- `updateMemberRole`: member ka role validate karke update karta hai.
- `deleteMember`: project membership remove karta hai.

**Humne yeh kyu kiya:** Controllers HTTP request/response, authorization aur model operations ko coordinate karte hain aur `ApiResponse`/`ApiError` ka consistent format use karte hain.

## 8. Tasks, subtasks aur notes ke models

### `src/models/task.models.js`

Task me title, description, project, assignee, assigner, status aur attachments store hote hain. Status constants se allowed values control hoti hain.

### `src/models/subtask.models.js`

Subtask ko parent `Task` se link karta hai. `isCompleted` member completion status store karta hai aur `createdBy` creator ko reference karta hai.

### `src/models/note.models.js`

Project note ko project aur creator se link karta hai aur note ka `content` store karta hai.

**Humne yeh kyu kiya:** Alag schemas se project-management data clearly separated, queryable aur maintainable rehta hai.

## 9. Shared utilities

### `src/utils/constants.js`

User roles aur task statuses ke fixed values define karta hai. `Object.values()` se validation ke liye allowed-values arrays banayi jati hain.

### `src/utils/Api-Response.js`

Successful responses ka common shape banata hai: `statusCode`, `data`, `message` aur `success`.

### `src/utils/api-error.js`

Custom error class hai jo `statusCode`, `message`, `errors`, `success` aur `data` fields provide karti hai.

### `src/utils/async-handler.js`

Async controller errors ko Express ke `next()` flow tak forward karne ke liye wrapper provide karta hai. Isse har controller me repetitive `try/catch` kam hota hai.

### `src/utils/mail.js`

- Nodemailer se SMTP transporter banata hai.
- Mailgen se plain-text aur HTML email generate karta hai.
- Email verification aur forgot-password email content helpers provide karta hai.

**Humne yeh kyu kiya:** Email sending ko reusable utility me rakhne se controllers me SMTP aur email-formatting details repeat nahi hoti.

## 10. File uploads

### `src/middlewares/multer.middleware.js`

- Uploaded files ko `public/images` me save karta hai.
- Filename ke start me timestamp add karta hai.
- File size ko `1 MB` tak limit karta hai.

**Humne yeh kyu kiya:** Multer multipart/form-data ko handle karta hai aur size limit server storage misuse ko reduce karti hai.

## 11. Current implementation notes

Yeh points future fixes ke liye important hain:

- `src/app.js` me CORS methods me `"GET "` ke end me extra space hai; ise `"GET"` hona chahiye.
- `src/controllers/auth.controller.js` me kuch existing typos/logic issues hain, jaise `statu()` aur cookie option `httponly` ki jagah `httpOnly` hona chahiye.
- Email verification flow me `User.findOne(...)` ko `await` ki zarurat hai.
- `src/controllers/project.controllers.js` me `getProjectMembers` ko `Project.findById(projectId)` use karna chahiye, `req.params` nahi.
- Project creation aur membership creation do database writes hain; production me transaction use karna safer hoga.
- Task aur note models present hain, lekin current `src/app.js` me task/note routers mounted nahi dikhte.
- `src/models/task.models.js` me exported model ka naam `Taks` hai; future code me naming ko `Task` karna clarity ke liye better hoga.
- Production me uploaded filename sanitize karna aur MIME/type validation add karna chahiye.

## 12. Short request flow

```text
Client request
    -> Express app (`src/app.js`)
    -> Router (`src/routes/`)
    -> Validation/auth middleware
    -> Controller (`src/controllers/`)
    -> Model (`src/models/`)
    -> MongoDB
    -> ApiResponse or ApiError
    -> Client
```

Is flow ka main benefit separation of responsibility hai: route mapping routes me, access control middleware me, request handling controllers me, aur database rules models me rehte hain.
