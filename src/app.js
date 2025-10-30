import express from "express";
import CORS from "cors";
import cookieParser from "cookie-parser";
const app = express();


// basic configurations
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());


// cors configurations
app.use(
  CORS({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:3000", //5173 is for vite dev server
    methods: ["GET ", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["content-type", "Authorization"],
  })
);
// import the routes

import healthcheckRouter from "./routes/healtcheck.routes.js";
import authRouter from "./routes/auth.route.js";
import projectRouter from "./routes/project.routes.js";
app.use("/api/v1/healthcheck", healthcheckRouter);

app.use("/api/v1/auth", authRouter);

app.use("/api/v1/projects", projectRouter);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

export default app;
