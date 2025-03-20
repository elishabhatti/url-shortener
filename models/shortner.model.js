// import fs from "fs/promises";
// import path from "path";

// const DATA_FILE = path.join("data", "links.json");

// export const loadLinks = async () => {
//   try {
//     const data = await fs.readFile(DATA_FILE, "utf-8");
//     return JSON.parse(data);
//   } catch (error) {
//     if (error.code === "ENOENT") {
//       await fs.writeFile(DATA_FILE, JSON.stringify({}), "utf-8");
//       return {};
//     }
//     throw error;
//   }
// };

// export const saveLinks = async (links) => {
//   await fs.writeFile(DATA_FILE, JSON.stringify(links, null, 2), "utf-8");
// };

// import { dbClient } from "../config/db-client.js";
// import { env } from "../config/env.js";

// const db = dbClient.db(env.MONGODB_DATABASE_NAME);
// const shortnerCollection = db.collection("shorteners");

import { db } from "../config/db-client.js";
export const loadLinks = async () => {
  // return shortnerCollection.find().toArray();
  const [rows] = await db.execute(`select * from short_links`);
  return rows;
};

export const insertShortLink = async ({ url, shortCode }) => {
  // return shortnerCollection.insertOne(link);
  const [result] = await db.execute(
    "insert into short_links(short_code, url) values(?,?)",
    [shortCode, url]
  );
  return result;
};

export const getLinkByShortCode = async (shortCode) => {
  // return await shortnerCollection.findOne({ shortCode });
  const [rows] = await db.execute(
    "SELECT * FROM short_links WHERE short_code = ?",
    [shortCode]
  );

  if (rows.length > 0) {
    return rows[0];
  } else {
    return null;
  }
};
