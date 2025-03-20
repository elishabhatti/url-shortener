import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const loadLinks = async () => {
  //   const [rows] = await db.execute(`select * from short_links`);
  //   return rows;

  const allShortLinks = await prisma.shortLinks.findMany();
  return allShortLinks;
};

export const getLinkByShortCode = async (shortCode) => {
  //   const [rows] = await db.execute(
  //     "SELECT * FROM short_links WHERE short_code = ?",
  //     [shortCode]
  //   );
  const shortLink = await prisma.shortLinks.findUnique({
    where: { shortCode: shortCode },
  });
  return shortLink;
};
export const insertShortLink = async ({ url, shortCode }) => {
  // return shortnerCollection.insertOne(link);
  //   const [result] = await db.execute(
  //     "insert into short_links(short_code, url) values(?,?)",
  //     [shortCode, url]
  //   );
  //   return result;

  const newShortLink = await prisma.shortLinks.create({
    data: { shortCode, url },
  });
  return newShortLink;
};
