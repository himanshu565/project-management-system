import { body } from "express-validator";

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("email is requred")
      .isEmail()
      .withMessage("Email is not valid"),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("username is required")
      .isLowercase()
      .withMessage("username must be in lowercase")
      .isLength({ min: 3 })
      .withMessage("username must be of atleast 3 character long "),

    body("password").trim().notEmpty().withMessage("password cannot be empty"),

    body("fullname").trim().optional(),
  ];
};

const userLoginValidator = () => {
  return [
    body("email").trim().optional().isEmail().withMessage("email is not valid"),
    body("password").trim().notEmpty().withMessage("password cannot be empty"),
    body("username")
      .trim()
      .notEmpty()
      .withMessage("username is required")
      .isLowercase()
      .withMessage("username must be in lowercase")
      .isLength({ min: 3 })
      .withMessage("username must be of atleast 3 character long "),
  ];
};

export { userRegisterValidator, userLoginValidator };
