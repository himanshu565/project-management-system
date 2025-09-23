import { ApiResponse } from "../utils/Api-Response.js";

const healthcheck = async (req, res, next) => {
  try {
    const user  = await getUserFromDB()
    res
      .status(200)
      .json(new ApiResponse(200, { message: " server is running fine" }));
  } catch (error) {
    
  }
};
export  { healthcheck };
