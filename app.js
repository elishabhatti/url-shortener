import express from "express";
import cookieParser from "cookie-parser";
import session from "express-session";
import flash from "connect-flash";
import requestIp from "request-ip";

import { shortenedRoutes } from "./routes/shortener.routes.js";
import { authRouter } from "./routes/auth.routes.js";
import { verifyAuthentication } from "./middlewares/verify-auth-middleware.js";

const app = express();
const PORT = process.env.PORT;

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
app.use(requestIp.mw());
app.use(verifyAuthentication);
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

app.set("view engine", "ejs");
app.set("views", "./views");
app.use(express.static("public"));
app.use(authRouter);
app.use(shortenedRoutes);

app.listen(PORT);
