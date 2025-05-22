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
  postForgotPassword,
  getResetPasswordTokenPage,
  postResetPasswordToken,
  getGoogleLoginPage,
  getGoogleLoginCallback,
  getGithubLoginPage,
  getGithubLoginCallback,
  getSetPasswordPage,
  postSetPassword,
} from "../controllers/auth.controller.js";
import multer from "multer";
import path from "path";

const router = Router();

router.route("/login").get(getLoginPage).post(postLogin);
router.route("/register").get(getRegistrationPage).post(postRegister);
router.route("/profile").get(getProfilePage);
router.route("/verify-email").get(getVerifyEmailPage);
router.route("/resend-verification-link").post(resendVerificationLink);
router.route("/verify-email-token").get(verifyEmailToken);

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/uploads/avatar");
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}_${Math.random()}${ext}`);
  },
});

const avatarFileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only Imge files are allowed"), false);
  }
};

const avatarUpload = multer({
  storage: avatarStorage,
  fileFilter: avatarFileFilter,
  limits: { fileSize: 5 * 1024 * 1024 },
});

router
  .route("/edit-profile")
  .get(getEditProfilePage)
  .post(avatarUpload.single("avatar"), postEditProfile);
router.route("/google").get(getGoogleLoginPage);
router.route("/github").get(getGithubLoginPage);

router.route("/google/callback").get(getGoogleLoginCallback);
router.route("/github/callback").get(getGithubLoginCallback);

router
  .route("/change-password")
  .get(getChangePasswordPage)
  .post(postChangePassword);

router.route("/set-password").get(getSetPasswordPage).post(postSetPassword);

router
  .route("/reset-password")
  .get(getResetPasswordPage)
  .post(postForgotPassword);
router
  .route("/reset-password/:token")
  .get(getResetPasswordTokenPage)
  .post(postResetPasswordToken);
router.route("/me").get(getMe);
router.route("/logout").get(logoutUser);

export const authRouter = router;
