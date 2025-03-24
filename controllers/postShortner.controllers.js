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
        .send("Short code already exists. Please choose another.");
    }

    // Validate URL (basic check)
    try {
      new URL(url);
    } catch (error) {
      return res.status(400).send("Invalid URL.");
    }

    // links[finalShortCode] = url; // Use finalShortCode instead of shortCode
    // await saveLinks(links);

    // await saveLinks({ url, shortCode });
    await insertShortLink({ url, shortCode: finalShortCode });

    return res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
};

export const getShortnerPage = async (req, res) => {
  try {
    // const file = await fs.readFile(path.join("views", "index.html"));
    // const links = await loadLinks();
    const links = await getAllShortLinks();
    // let isLoggedIn = req.headers.cookie;
    // isLoggedIn = Boolean(
    //   isLoggedIn
    //     ?.split(";")
    //     ?.find((cookie) => cookie.trim().startsWith("isLoggedIn"))
    //     ?.split("=")[1]
    // );
    
    let isLoggedIn = req.cookies.isLoggedIn;
    console.log(isLoggedIn);

    return res.render("index", { links, host: req.host, isLoggedIn });
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal server error");
  }
};

export const redirectToShortLinks = async (req, res) => {
  try {
    const { shortCode } = req.params;
    // const links = await loadLi[nks();
    const link = await getShortLinkByShortCode(shortCode);

    // if (!links[shortCode]) return res.status(404).send("404 error occurred");
    if (!link) return res.redirect("/404");
    return res.redirect(link.url);
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal server error");
  }
};
