import dotenv from "dotenv";
dotenv.config();

export const env = {
  MONGODB_URL: process.env.MONGODB_URL,
  MONGODB_DATABASE_NAME: process.env.MONGODB_DATABASE_NAME,
};
