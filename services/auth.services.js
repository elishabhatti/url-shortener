import { db } from "../config/db.js";
import {
  sessionsTable,
  shortLink,
  users,
  verifyEmailTokensTable,
} from "../drizzle/schema.js";
import { and, eq, gte, lt, sql } from "drizzle-orm";
import path from "path";
import fs from "fs/promises";
import {
  REFRESH_TOKEN_EXPIRY,
  ACCESS_TOKEN_EXPIRY,
  MILLISECONDS_PER_SECOND,
} from "../config/constants.js";
// import { sendEmail } from "../lib/nodemailer.js";
import { sendEmail } from "../lib/send-email.js";
import argon2 from "argon2";
import crypto from "crypto";
import ejs from "ejs";
import jwt from "jsonwebtoken";
import mjml2html from "mjml";

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
    expiresIn: REFRESH_TOKEN_EXPIRY / MILLISECONDS_PER_SECOND,
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
  const [user] = await db.select().from(users).where(eq(users.id, userId)); // ✅ Correct column
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
      isEmailValid: user.isEmailValid,
      sessionId: currentSession.id,
    };

    const newAccessToken = createAccessToken(userInfo);
    const newRefreshToken = createRefreshToken(currentSession.id);

    return {
      newAccessToken,
      newRefreshToken,
      user, // ✅ Return user instead of userInfo
    };
  } catch (error) {
    console.error("Error refreshing token:", error);
    throw new Error("Refresh token invalid or expired");
  }
};

export const clearUserSession = (sessionId) => {
  return db.delete(sessionsTable).where(eq(sessionsTable.id, sessionId));
};

export const authenticateUser = async ({ req, res, user, name, email }) => {
  const session = await createSession(user.id, {
    ip: req.clientIp,
    userAgent: req.headers["user-agent"],
  });

  const accessToken = createAccessToken({
    id: user.id,
    name: user.name || name,
    email: user.email || email,
    isEmailValid: false,
    sessionId: session.id,
  });

  const refreshToken = createRefreshToken(session.id);
  const baseConfig = { httpOnly: true, secure: true };

  res.cookie("access_token", accessToken, {
    ...baseConfig,
    maxAge: ACCESS_TOKEN_EXPIRY,
  });

  res.cookie("refresh_token", refreshToken, {
    ...baseConfig,
    maxAge: REFRESH_TOKEN_EXPIRY,
  });
};

export const getAllShortLinks = async (userId) => {
  return await db.select().from(shortLink).where(eq(shortLink.userId, userId));
};

export const generateRandomToken = (digit = 8) => {
  const min = 10 ** (digit - 1);
  const max = 10 ** digit - 1;

  return crypto
    .randomInt(min, max + 1)
    .toString()
    .padStart(digit, "0");
};

export const insertVerifyEmailToken = async ({ userId, token }) => {
  return db.transaction(async (tx) => {
    try {
      await tx
        .delete(verifyEmailTokensTable)
        .where(lt(verifyEmailTokensTable.expiresAt, sql`CURRENT_TIMESTAMP`));
      await tx
        .delete(verifyEmailTokensTable)
        .where(lt(verifyEmailTokensTable.userId, userId));

      await tx.insert(verifyEmailTokensTable).values({ userId, token });
    } catch (error) {
      console.error("Failed to insert verification token", error);
      throw new Error("Unable to create verification token");
    }
  });
};

// export const createVerifyEmailLink = async ({ email, token }) => {
//   const uriEncodedEmail = encodeURIComponent(email);
//   return `${process.env.FRONTEND_URL}/verify-email-token?token=${token}$email=${uriEncodedEmail}`;
// };

export const createVerifyEmailLink = async ({ email, token }) => {
  const url = new URL(`${process.env.FRONTEND_URL}/verify-email-token`);
  url.searchParams.append("token", token);
  url.searchParams.append("email", email);

  return url.toString();
};

// export const findVerificationEmailToken = async ({ token, email }) => {
//   const tokenData = await db
//     .select({
//       userId: verifyEmailTokensTable.userId,
//       token: verifyEmailTokensTable.token,
//       expiresAt: verifyEmailTokensTable.expiresAt,
//     })
//     .from(verifyEmailTokensTable)
//     .where(
//       and(
//         eq(verifyEmailTokensTable.token, token),
//         gte(verifyEmailTokensTable.expiresAt, sql`CURRENT_TIMESTAMP`)
//       )
//     );

//   if (!tokenData.length) {
//     return null;
//   }

//   const { userId, token: retrievedToken, expiresAt } = tokenData[0];

//   const userData = await db
//     .select({ userId: users.id, email: users.email })
//     .from(users)
//     .where(eq(users.id, userId));

//   if (!userData.length) {
//     return null;
//   }

//   return {
//     userId: userData[0].userId,
//     email: userData[0].email,
//     token: retrievedToken,
//     expiresAt: expiresAt,
//   };
// };

export const findVerificationEmailToken = async ({ token, email }) => {
  return await db
    .select({
      userId: users.id,
      email: users.email,
      token: verifyEmailTokensTable.token,
      expiresAt: verifyEmailTokensTable.expiresAt,
    })
    .from(verifyEmailTokensTable)
    .where(
      and(
        eq(verifyEmailTokensTable.token, token),
        eq(users.email, email),
        gte(verifyEmailTokensTable.expiresAt, sql`CURRENT_TIMESTAMP`)
      )
    )
    .innerJoin(users, eq(verifyEmailTokensTable.userId, users.id));
};

export const verifyUserEmailAndUpdate = async (email) => {
  return db
    .update(users)
    .set({ isEmailValid: true })
    .where(eq(users.email, email));
};

export const clearVerifyEmailTokens = async (userId) => {
  // const [user] = await db.select().from(users).where(eq(users.email, email));
  return await db
    .delete(verifyEmailTokensTable)
    .where(eq(verifyEmailTokensTable.userId, userId));
};

export const sendNewVerifyEmailLink = async ({ email, userId }) => {
  const randomToken = generateRandomToken();

  await insertVerifyEmailToken({ userId, token: randomToken });

  const verifyEmailLink = await createVerifyEmailLink({
    email,
    token: randomToken,
  });

  const mjmlTemplate = await fs.readFile(
    path.join(import.meta.dirname, "..", "emails", "verify-email.mjml"),
    "utf-8"
  );

  const filledTemplate = ejs.render(mjmlTemplate, {
    code: randomToken,
    link: verifyEmailLink,
  });

  const htmlOutput = mjml2html(filledTemplate).html;
  console.log("Email", email, "userId", userId);

  sendEmail({
    to: email,
    subject: "Verify your email",
    html: htmlOutput,
  }).catch((error) => console.error(error));
};
