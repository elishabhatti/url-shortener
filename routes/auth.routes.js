import { Router } from "express";
import {
  getRegistrationPage,
  getLoginPage,
  postLogin,
  postRegister,
} from "../controllers/auth.controller.js";

const router = Router();

// router.get("/register", getRegistrationPage);
router.route("/login").get(getLoginPage).post(postLogin);
router.route("/register").get(getRegistrationPage).post(postRegister);

export const authRouter = router;
