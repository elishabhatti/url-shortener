// import { PrismaClient } from "@prisma/client";

// const prisma = new PrismaClient();

// export const loadLinks = async () => {
//   //   const [rows] = await db.execute(`select * from short_links`);
//   //   return rows;

//   const allShortLinks = await prisma.shortLinks.findMany();
//   return allShortLinks;
// };

// export const getLinkByShortCode = async (shortCode) => {
//   //   const [rows] = await db.execute(
//   //     "SELECT * FROM short_links WHERE short_code = ?",
//   //     [shortCode]
//   //   );
//   const shortLink = await prisma.shortLinks.findUnique({
//     where: { shortCode: shortCode },
//   });
//   return shortLink;
// };
// export const insertShortLink = async ({ url, shortCode }) => {
//   // return shortnerCollection.insertOne(link);
//   //   const [result] = await db.execute(
//   //     "insert into short_links(short_code, url) values(?,?)",
//   //     [shortCode, url]
//   //   );
//   //   return result;

//   const newShortLink = await prisma.shortLinks.create({
//     data: { shortCode, url },
//   });
//   return newShortLink;
// };

import { eq } from "drizzle-orm";
import { db } from "../config/db.js";
import { shortLink } from "../drizzle/schema.js";

export const getAllShortLinks = async (userId) => {
  return await db.select().from(shortLink).where(eq(shortLink.userId, userId));
};

export const getShortLinkByShortCode = async (shortCode) => {
  const [result] = await db
    .select()
    .from(shortLink)
    .where(eq(shortLink.shortCode, shortCode));
  return result;
};
export const insertShortLink = async ({ url, shortCode, userId }) => {
  await db.insert(shortLink).values({ url, shortCode, userId });
};

export const findShortLinkById = async (id) => {
  const [result] = await db
    .select()
    .from(shortLink)
    .where(eq(shortLink.id, id));
  return result;
};
// updateShortCodeById
export const updateShortCodeById = async ({ id, url, shortCode }) => {
  await db.update(shortLink) 
    .set({ url, shortCode })
    .where(eq(shortLink.id, id));
};

// deleteShortCodeById
export const deleteShortCodeById = async (id) => {
  const [result] = await db.delete(shortLink).where(eq(shortLink.id, id));
  return result;
};
