
import { body } from "express-validator"


const userRegisterValidator = () =>{
    return [

        body("email")
        .trim()
        .isEmpty()
        .withMessage("email is requred")
        .isEmail()
        .withMessage("Email is not valid"),

        body("username")
        .trim()
        .isEmpty()
        .withMessage("username is required")
        .isLowercase()
        .withMessage("username must be in lowercase")
        .isLength({min:3})
        .withMessage("username must be of atleast 3 character long "),

        body("password")
        .trim()
        .isEmpty()
        .withMessage("password cannot be empty"),

        body("fullname")
        .trim()
        .optional()
        
        


    ]
}
export {userRegisterValidator};