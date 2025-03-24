import { Router } from "express";
import {
  getRegistrationPage,
  getLoginPage,
  postLogin,
} from "../controllers/auth.controller.js";

const router = Router();

router.get("/register", getRegistrationPage);
router.route("/login").get(getLoginPage).post(postLogin);

export const authRouter = router;
