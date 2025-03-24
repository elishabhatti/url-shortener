import { Router } from "express";
// import * as authControllers from "../controllers/auth.controller.js";
import { getRegistrationPage, getLoginPage } from "../controllers/auth.controller.js";

const router = Router();

router.get("/register", getRegistrationPage);
router.get("/login", getLoginPage); 

export const authRouter = router;
