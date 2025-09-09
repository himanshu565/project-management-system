import express from "express";
import CORS from "cors";
const app = express();


app.use(express.json({limit: "16kb"}));
app.use(express.urlencoded({extended :true ,limit :"16kb"}));
app.use(express.static("public"));

app.use(CORS( {
  origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
  methods: ['GET ','POST','PUT', 'PATCH', 'DELETE','OPTIONS'],
  credentials: true,
  allowedHeaders: ['content-type','Authorization'],

}
));

app.get("/", (req, res) => {
  res.send("Hello World!");
});





export default app;