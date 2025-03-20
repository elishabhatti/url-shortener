// import dotenv from "dotenv";
// dotenv.config();

// export const env = {
//   MONGODB_URL: process.env.MONGODB_URL,
//   MONGODB_DATABASE_NAME: process.env.MONGODB_DATABASE_NAME,
// };

import dotenv from "dotenv";
dotenv.config();

import { z } from "zod";

export const env = z.object({
  PORT: z.coerce.number().default(3000),
  DATABASE_HOST: z.string(),
  DATABASE_USER: z.string(),
  DATABASE_NAME: z.string(),
  DATABASE_PASSWORD: z.string(),
}).parse(process.env);
