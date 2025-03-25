import {
  postUrlShortner,
  getShortnerPage,
  redirectToShortLinks,
} from "../controllers/postShortner.controllers.js";

import { Router } from "express";

const router = Router();

router.post("/", postUrlShortner);
router.get("/", getShortnerPage);
router.get("/:shortCode", redirectToShortLinks);

// export default router;
export const shortenedRoutes = router;
