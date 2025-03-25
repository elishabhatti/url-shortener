import express from "express";
import { shortenedRoutes } from "./routes/shortener.routes.js";
import { authRouter } from "./routes/auth.routes.js";
import cookieParser from "cookie-parser";
import { verifyAuthentication } from "./middlewares/verify-auth-middleware.js";

const app = express();
const PORT = 3000;

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(verifyAuthentication);
app.set("view engine", "ejs");
app.set("views", "./views");
app.use(express.static("public"));
app.use(authRouter);
app.use(shortenedRoutes);

app.listen(PORT);
