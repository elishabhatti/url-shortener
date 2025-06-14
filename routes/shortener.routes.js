import {
  postUrlShortner,
  getShortnerPage,
  redirectToShortLinks,
  getShortenerEditPage,
  deleteShortCode,
  EditShortCode,
} from "../controllers/postShortner.controller.js";

import { Router } from "express";

const router = Router();

router.post("/", postUrlShortner);
router.get("/", getShortnerPage);
router.get("/:shortCode", redirectToShortLinks);
router.route("/edit/:id").get(getShortenerEditPage).post(EditShortCode);
router.route("/delete/:id").post(deleteShortCode);

export const shortenedRoutes = router;
