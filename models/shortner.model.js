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

import { dbClient } from "../config/db-client.js";
import { env } from "../config/env.js";

const db = dbClient.db(env.MONGODB_DATABASE_NAME);
const shortnerCollection = db.collection("shorteners");

export const loadLinks = async () => {
  return shortnerCollection.find().toArray();
};

export const saveLinks = async (link) => {
  return shortnerCollection.insertOne(link);
};

export const getLinkByShortCode = async (shortCode) => {
  return await shortnerCollection.findOne({ shortCode });
};
