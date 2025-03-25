import { db } from "../config/db.js";
import { users } from "../drizzle/schema.js";
import { eq } from "drizzle-orm";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

export const getUserByEmail = async (email) => {
  const [user] = await db.select().from(users).where(eq(users.email, email));
  return user;
};
export const createUser = async ({ name, email, password }) => {
  return await db
    .insert(users)
    .values({ name, email, password })
    .$returningId();
};

export const hashPassword = async (password) => {
  return await argon2.hash(password);
};
export const comparePassword = async (password, hash) => {
  return await argon2.verify(hash, password);
};

export const generateToken = ({ id, name, email }) => {
  return jwt.sign({ id, name, email }, process.env.JWT_SECRET, {expiresIn: "30d"});
};
