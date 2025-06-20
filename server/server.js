import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import { connectDB } from "./config/mongodb.js";
import { authRouter } from "./routes/authRoutes.js";
import { userRouter } from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 4000;
connectDB();

const allowedOrigins = ["https://auth-jkx2.vercel.app"];

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: allowedOrigins, credentials: true }));

app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

app.get("/", (_, res) => {
  res.send("This IS work");
});

app.listen(port, () => {
  console.log(`Server started on PORT: http://localhost:${port}`);
});
