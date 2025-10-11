import { validationResult } from "express-validator";
import { ApiError } from "next/dist/server/api-utils";


export const validate = (req, res, next)=>{
    const errors = validationResult(req);
    if(errors.isEmpty()){
        return next();
    
    }
    const extractedError = [];
    errors.array().map((err)=>
    extractedError.push(
        {
            [err.path]: err.msg,
        }),

    );
    throw new ApiError(422,"received data is not valid",extractedError);
};