import crypto from "crypto";
import {
  getAllShortLinks,
  getShortLinkByShortCode,
  insertShortLink,
} from "../services/shortener.services.js";

export const postUrlShortner = async (req, res) => {
  try {
    const { url, shortCode } = req.body;
    const finalShortCode = shortCode || crypto.randomBytes(4).toString("hex");
    const links = await getShortLinkByShortCode(finalShortCode);
    if (links) {
      return res
        .status(400)
        .send("Chosse Another Name.");
    }
    try {
      new URL(url);
    } catch (error) {
      return res.status(400).send("Invalid URL.");
    }
    await insertShortLink({ url, shortCode: finalShortCode, userId: req.user.id });

    return res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
};

export const getShortnerPage = async (req, res) => {
  try {
    if (!req.user) return res.redirect("/login");
    const links = await getAllShortLinks(req.user.id);
    return res.render("index", { links, host: req.host });
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal server error");
  }
};

export const redirectToShortLinks = async (req, res) => {
  try {
    const { shortCode } = req.params;
    const link = await getShortLinkByShortCode(shortCode);
    if (!link) return res.redirect("/404");
    return res.redirect(link.url);
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal server error");
  }
};
