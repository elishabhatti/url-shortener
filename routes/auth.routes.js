import { Router } from "express";
import {
  getRegistrationPage,
  getLoginPage,
  getMe,
  postLogin,
  postRegister,
  logoutUser,
  getProfilePage,
  getVerifyEmailPage,
} from "../controllers/auth.controller.js";

const router = Router();

// router.get("/register", getRegistrationPage);
router.route("/login").get(getLoginPage).post(postLogin);
router.route("/register").get(getRegistrationPage).post(postRegister);
router.route("/profile").get(getProfilePage)
router.route("/verify-email").get(getVerifyEmailPage)
router.route("/me").get(getMe);
router.route("/logout").get(logoutUser);

export const authRouter = router;
