import {
  postUrlShortner,
  getShortnerPage,
  redirectToShortLinks,
  getShortenerEditPage
} from "../controllers/postShortner.controllers.js";

import { Router } from "express";

const router = Router();

router.post("/", postUrlShortner);
router.get("/", getShortnerPage);
router.get("/:shortCode", redirectToShortLinks);
router.route("/edit/:id").get(getShortenerEditPage);

export const shortenedRoutes = router;
