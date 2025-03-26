import { Router } from "express";
import {
  getRegistrationPage,
  getLoginPage,
  getMe,
  postLogin,
  postRegister,
  logoutUser,
} from "../controllers/auth.controller.js";

const router = Router();

// router.get("/register", getRegistrationPage);
router.route("/login").get(getLoginPage).post(postLogin);
router.route("/register").get(getRegistrationPage).post(postRegister);
router.route("/me").get(getMe);
router.route("/logout").get(logoutUser);

export const authRouter = router;
