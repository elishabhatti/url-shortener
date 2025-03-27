import crypto from "crypto";
import z from "zod";
import {
  getAllShortLinks,
  getShortLinkByShortCode,
  findShortLinkById,
  insertShortLink,
  deleteShortCodeById,
  updateShortCodeById,
} from "../services/shortener.services.js";

export const postUrlShortner = async (req, res) => {
  try {
    const { url, shortCode } = req.body;

    const finalShortCode = shortCode || crypto.randomBytes(4).toString("hex");
    const links = await getShortLinkByShortCode(finalShortCode);

    if (links) {
      return res.redirect("/");
    }

    await insertShortLink({
      url,
      shortCode: finalShortCode,
      userId: req.user.id,
    });
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
      return res.redirect("/404");
    }
    return res.redirect(link.url);
  } catch (error) {
    console.error(error);
    req.flash("errors", "Internal server error.");
    return res.redirect("/");
  }
};

// getShortenerEditPage
export const getShortenerEditPage = async (req, res) => {
  if (!req.user) return res.redirect("/login");
  // const { id } = req.params;
  const { data: id, error } = z.coerce.number().int().safeParse(req.params.id);
  if (error) return res.redirect("/404");

  try {
    const shortLink = await findShortLinkById(id);
    if (!shortLink) return res.redirect("/404");

    res.render("edit-shortLink", {
      id: shortLink.id,
      url: shortLink.url,
      shortCode: shortLink.shortCode,
      errors: req.flash("errors"),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).send("Inter serval Error");
  }
};

export const deleteShortCode = async (req, res) => {
  if (!req.user) return res.redirect("/login");

  try {
    const { data: id, error } = z.coerce
      .number()
      .int()
      .safeParse(req.params.id);
    if (error) return res.redirect("/404");

    await deleteShortCodeById(id);
    res.redirect("/");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Inter serval Error");
  }
};
// EditShortCode
export const EditShortCode = async (req, res) => {
  if (!req.user) return res.redirect("/login");

  try {
    const { data: id, error } = z.coerce.number().int().safeParse(req.params.id);
    if (error) return res.redirect("/404");

    // ✅ Request body se URL aur shortCode fetch karo
    const { url, shortCode } = req.body;
    if (!url || !shortCode) {
      req.flash("errors", "URL and ShortCode are required");
      return res.redirect(`/edit/${id}`);
    }

    await updateShortCodeById({ id, url, shortCode });
    res.redirect("/");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal Server Error");
  }
};
