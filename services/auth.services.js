import { db } from "../config/db.js";
import { sessionsTable, users } from "../drizzle/schema.js";
import { eq } from "drizzle-orm";
import {
  ACCESS_TOKEN_EXPIRY,
  MILLISECONDS_PER_SECOND,
} from "../config/constants.js";

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
export const createSession = async (userId, { ip, userAgent }) => {
  const [session] = await db
    .insert(sessionsTable)
    .values({
      userId,
      ip,
      userAgent,
    })
    .$returningId();

  return session;
};

export const createAccessToken = ({ id, name, email, sessionId }) => {
  return jwt.sign({ id, name, email, sessionId }, process.env.JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY / MILLISECONDS_PER_SECOND,
  });
};
export const createRefreshToken = (sessionId) => {
  return jwt.sign({ sessionId }, process.env.JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY / MILLISECONDS_PER_SECOND,
  });
};
export const verifyJwtToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

export const findSessionById = async (sessionId) => {
  const [session] = await db
    .select()
    .from(sessionsTable)
    .where(eq(sessionsTable.id, sessionId));
  return session;
};
export const findByUserId = async (userId) => {
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId));  // ✅ Correct column
  return user;
};


export const refreshTokens = async (refreshToken) => {
  try {
    const decodedToken = verifyJwtToken(refreshToken);
    const currentSession = await findSessionById(decodedToken.sessionId);
    if (!currentSession || !currentSession.valid) {
      throw new Error("Invalid Session");
    }

    const user = await findByUserId(currentSession.userId);
    if (!user) throw new Error("Invalid User");

    const userInfo = {
      id: user.id,
      name: user.name,
      email: user.email,
      sessionId: currentSession.id, 
    };

    const newAccessToken = createAccessToken(userInfo);
    const newRefreshToken = createRefreshToken(currentSession.id);

    return {
      newAccessToken,
      newRefreshToken,
      user,  // ✅ Return user instead of userInfo
    };
  } catch (error) {
    console.error("Error refreshing token:", error);
    throw new Error("Refresh token invalid or expired");
  }
};

