import express from "express";
import { shortenedRoutes } from "./routes/shortener.routes.js";
import { authRouter } from "./routes/auth.routes.js";
import cookieParser from "cookie-parser";
import { verifyAuthentication } from "./middlewares/verify-auth-middleware.js";
import session from "express-session";
import flash from "connect-flash";

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.JWT_SECRET,
    resave: true,
    saveUninitialized: false,
  })
);
app.use(flash());
app.use(verifyAuthentication);
app.use((req, res, next) => {
  res.locals.user = req.user;
  return next();
});
app.set("view engine", "ejs");
app.set("views", "./views");
app.use(express.static("public"));
app.use(authRouter);
app.use(shortenedRoutes);

app.listen(PORT);
