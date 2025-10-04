import { ApiResponse } from "../utils/Api-Response.js";
import { asyncHandler } from "../utils/async-handler.js";

// const healthcheck = async (req, res, next) => {
//   try {
//     const user  = await getUserFromDB()
//     res
//       .status(200)
//       .json(new ApiResponse(200, { message: " server is running fine" }));
//   } catch (error) {
//     next()
//   }
// };

const healthcheck = asyncHandler(async (req, res) => {
  res
     .status(200).json(new ApiResponse(200, { message: " server is running fine" }));
});
export { healthcheck };
