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
      req.flash("errors", "Short code already taken. Choose another.");
      return res.redirect("/");
    }

    try {
      new URL(url);
    } catch (error) {
      req.flash("errors", "Invalid URL.");
      return res.redirect("/");
    }

    await insertShortLink({
      url,
      shortCode: finalShortCode,
      userId: req.user.id,
    });

    req.flash("success", "Short URL created successfully!");
    return res.redirect("/");
  } catch (error) {
    console.error(error);
    req.flash("errors", "Internal server error.");
    return res.redirect("/");
  }
};

export const getShortnerPage = async (req, res) => {
  try {
    if (!req.user) return res.redirect("/login");

    const links = await getAllShortLinks(req.user.id);
    
    // Retrieve and clear flash messages

    return res.render("index", {
      links,
      host: req.host,
    });
  } catch (error) {
    console.error(error);
    req.flash("errors", "Internal server error.");
    return res.redirect("/");
  }
};


export const redirectToShortLinks = async (req, res) => {
  try {
    const { shortCode } = req.params;
    const link = await getShortLinkByShortCode(shortCode);
    if (!link) {
      req.flash("errors", "Short link not found.");
      return res.redirect("/404");
    }
    return res.redirect(link.url);
  } catch (error) {
    console.error(error);
    req.flash("errors", "Internal server error.");
    return res.redirect("/");
  }
};