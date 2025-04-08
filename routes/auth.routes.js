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
  resendVerificationLink,
  verifyEmailToken,
  getEditProfilePage,
  postEditProfile,
  getChangePasswordPage,
  postChangePassword,
  getResetPasswordPage,
} from "../controllers/auth.controller.js";

const router = Router();

// router.get("/register", getRegistrationPage);
router.route("/login").get(getLoginPage).post(postLogin);
router.route("/register").get(getRegistrationPage).post(postRegister);
router.route("/profile").get(getProfilePage);
router.route("/verify-email").get(getVerifyEmailPage);
router.route("/resend-verification-link").post(resendVerificationLink);
router.route("/verify-email-token").get(verifyEmailToken);
router.route("/edit-profile").get(getEditProfilePage).post(postEditProfile);
router.route("/change-password").get(getChangePasswordPage).post(postChangePassword);
router.route("/reset-password").get(getResetPasswordPage)
// .post(postChangePassword);
router.route("/me").get(getMe);
router.route("/logout").get(logoutUser);

export const authRouter = router;
