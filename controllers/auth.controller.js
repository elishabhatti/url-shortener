import { sendEmail } from "../lib/send-email.js";
import {
  getUserByEmail,
  createUser,
  comparePassword,
  hashPassword,
  clearUserSession,
  authenticateUser,
  findByUserId,
  getAllShortLinks,
  findVerificationEmailToken,
  verifyUserEmailAndUpdate,
  clearVerifyEmailTokens,
  sendNewVerifyEmailLink,
  updateUserByName,
  updateUserPassword,
  createResetPasswordLink,
  getResetPasswordToken,
  clearResetPasswordToken,
  getUserWithOauthId,
  linkUserWithOauth,
  createUserWithOauth,
} from "../services/auth.services.js";
import fs from "fs/promises";
import path from "path";
import mjml2html from "mjml";
import ejs from "ejs";
import {
  forgotPasswordSchema,
  loginUserSchema,
  registerUserSchema,
  setPasswordSchema,
  verifyEmailSchema,
  verifyPasswordSchema,
  verifyUserSchema,
} from "../validators/auth-validator.js";
import { decodeIdToken, generateCodeVerifier, generateState } from "arctic";
import { OAUTH_EXCHANGE_EXPIRAY } from "../config/constants.js";
import { google } from "../lib/oauth/google.js";
import { github } from "../lib/oauth/github.js";

export const getRegistrationPage = (req, res) => {
  if (req.user) return res.redirect("/");
  return res.render("./auth/register", { errors: req.flash("errors") });
};

export const getLoginPage = (req, res) => {
  if (req.user) return res.redirect("/");
  return res.render("./auth/login", { errors: req.flash("errors") });
};

export const postLogin = async (req, res) => {
  if (req.user) return res.redirect("/");
  const { data, error } = loginUserSchema.safeParse(req.body);

  if (error) {
    const errors = error.errors[0].message;
    req.flash("errors", errors);
    return res.redirect("/login");
  }

  const { email, password } = data;
  const userExists = await getUserByEmail(email);

  if (!userExists) {
    req.flash("errors", "Invalid Password");
    return res.redirect("/login");
  }

  if (!userExists.password) {
    req.flash(
      "errors",
      "You have create account using social login. please login with your social account"
    );
    return res.redirect("/login");
  }

  const isPasswordValid = await comparePassword(password, userExists.password);
  if (!isPasswordValid) {
    req.flash("errors", "Invalid Password");
    return res.redirect("/login");
  }

  await authenticateUser({ req, res, user: userExists });

  if (!userExists.isEmailValid) {
    await sendNewVerifyEmailLink({ email, userId: userExists.id });
  }

  res.redirect("/");
};

export const postRegister = async (req, res) => {
  if (req.user) return res.redirect("/");

  const { data, error } = registerUserSchema.safeParse(req.body);

  if (error) {
    const errors = error.errors[0].message;
    req.flash("errors", errors);
    return res.redirect("/register");
  }

  const { name, email, password } = data;

  const userExists = await getUserByEmail(email);
  if (userExists) {
    req.flash("errors", "User already exists");
    return res.redirect("/register");
  }

  const hashedPassword = await hashPassword(password);
  const [user] = await createUser({ name, email, password: hashedPassword });

  await authenticateUser({ req, res, user });

  await sendNewVerifyEmailLink({ email, userId: user.id });
  res.redirect("/");
};

export const getMe = (req, res) => {
  if (!req.user) return res.send("Not Logged In");
  return res.send(`Hey ${req.user.name}`);
};

export const logoutUser = async (req, res) => {
  await clearUserSession(req.user.sessionId);

  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.redirect("/login");
};

export const getProfilePage = async (req, res) => {
  if (!req.user) return res.redirect("/login");

  const user = await findByUserId(req.user.id);
  if (!user) return res.redirect("/login");

  const userShortLinks = await getAllShortLinks(user.id);

  return res.render("auth/profile", {
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      isEmailValid: user.isEmailValid,
      avatarUrl: user.avatarUrl,
      hashPassword: Boolean(user.password),
      createdAt: user.createdAt,
      links: userShortLinks,
    },
  });
};

export const getVerifyEmailPage = async (req, res) => {
  const user = await findByUserId(req.user.id);
  if (!user || user.isEmailValid) return res.redirect("/");
  return res.render("auth/verify-email", { email: req.user.email });
};

export const resendVerificationLink = async (req, res) => {
  if (!req.user) return res.redirect("/");
  const user = await findByUserId(req.user.id);
  if (!user || user.isEmailValid) return res.redirect("/");

  await sendNewVerifyEmailLink({ email: req.user.email, userId: req.user.id });

  res.redirect("/verify-email");
};

export const verifyEmailToken = async (req, res) => {
  const { data, error } = verifyEmailSchema.safeParse(req.query);
  if (error) {
    return res.send("Verification link invalid or expired!");
  }

  const [token] = await findVerificationEmailToken(data);
  console.log("Verification Token", token);
  if (!token) res.send("Verification link invalid or expired!");

  await verifyUserEmailAndUpdate(token.email);

  // clearVerifyEmailTokens(token.email).catch(console.error(error));
  clearVerifyEmailTokens(token.userId).catch(console.error(error));

  return res.redirect("/profile");
};

export const getEditProfilePage = async (req, res) => {
  if (!req.user) return res.redirect("/");
  const user = await findByUserId(req.user.id);
  if (!user) return res.status(404).send("User not found");

  return res.render("auth/edit-profile", {
    name: user.name,
    avatarUrl: user.avatarUrl,
    errors: req.flash("errors"),
  });
};

export const postEditProfile = async (req, res) => {
  if (!req.user) return res.redirect("/");
  const { data, error } = verifyUserSchema.safeParse(req.body);

  if (error) {
    const errorMessages = error.errors.map((err) => err.message);
    req.flash("errors", errorMessages);
    return res.redirect("/edit-profile");
  }

  const fileUrl = req.file ? `uploads/avatar/${req.file.filename}` : undefined;

  await updateUserByName({
    userId: req.user.id,
    name: data.name,
    avatarUrl: fileUrl,
  });
  return res.redirect("/profile");
};

export const getChangePasswordPage = async (req, res) => {
  if (!req.user) return res.redirect("/");
  return res.render("auth/change-password", { errors: req.flash("errors") });
};

export const postChangePassword = async (req, res) => {
  const { data, error } = verifyPasswordSchema.safeParse(req.body);

  if (error) {
    const errorMessages = error.errors.map((err) => err.message);
    req.flash("errors", errorMessages);
    return res.redirect("/change-password");
  }
  const { currentPassword, newPassword } = data;
  const user = await findByUserId(req.user.id);
  if (!user) return res.status(404).send("User not found");

  const isPasswordValid = await comparePassword(currentPassword, user.password);
  if (!isPasswordValid) {
    req.flash("errors", "Cannot Password that you entered is invalid");
    return res.redirect("/change-passwork");
  }

  await updateUserPassword({ userId: user.id, newPassword });

  return res.redirect("/profile");
};

export const getResetPasswordPage = async (req, res) => {
  return res.render("auth/forgot-password", {
    formSubmitted: req.flash("formSubmitted")[0],
    errors: req.flash("errors"),
  });
};

export const postForgotPassword = async (req, res) => {
  const { data, error } = forgotPasswordSchema.safeParse(req.body);

  if (error) {
    const errorMessages = error.errors.map((err) => err.message);
    req.flash("errors", errorMessages[0]);
    return res.redirect("/change-password");
  }

  const user = await getUserByEmail(data.email);
  if (user) {
    const resetPasswordLink = await createResetPasswordLink({
      userId: user.id,
      email: user.email,
    });

    const mjmlTemplate = await fs.readFile(
      path.join(
        import.meta.dirname,
        "..",
        "emails",
        "reset-password-email.mjml"
      ),
      "utf-8"
    );

    const filledTemplate = ejs.render(mjmlTemplate, {
      name: user.name,
      link: resetPasswordLink,
    });

    const htmlOutput = mjml2html(filledTemplate).html;

    sendEmail({
      to: user.email,
      subject: "Verify your email",
      html: htmlOutput,
    }).catch((error) => console.error(error));
  }

  req.flash("formSubmitted", true);
  return res.redirect("/reset-password");
};

export const getResetPasswordTokenPage = async (req, res) => {
  const { token } = req.params;

  const passwordResetData = await getResetPasswordToken(token);
  if (!passwordResetData) return res.render("auth/wrong-reset-password-token");

  return res.render("auth/reset-password", {
    formSubmitted: req.flash("formSubmitted")[0],
    errors: req.flash("errors"),
    token,
  });
};

export const postResetPasswordToken = async (req, res) => {
  const { token } = req.params;

  const passwordResetData = await getResetPasswordToken(token);
  if (!passwordResetData) {
    req.flash("errors", "Password Token is not Matching");
    return res.render("auth/reset-password");
  }

  const { newPassword, confirmPassword } = req.body;
  console.log(newPassword, confirmPassword);

  const user = await findByUserId(passwordResetData.userId);

  await clearResetPasswordToken(user.id);
  await updateUserPassword({ userId: user.id, newPassword });

  return res.redirect("/login");
};

export const getGoogleLoginPage = (req, res) => {
  if (req.user) return res.redirect("/");

  try {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const url = google.createAuthorizationURL(state, codeVerifier, [
      "openid",
      "profile",
      "email",
    ]);

    const cookieConfig = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: OAUTH_EXCHANGE_EXPIRAY,
      sameSite: "lax",
    };

    res.cookie("google_oauth_state", state, cookieConfig);
    res.cookie("google_oauth_verifier", codeVerifier, cookieConfig);

    res.redirect(url.toString());
  } catch (error) {
    console.error(`Error from get login with google page ${error}`);
  }
};

export const getGoogleLoginCallback = async (req, res) => {
  const { code, state } = req.query;

  const {
    google_oauth_state: storeState,
    google_oauth_verifier: codeVerifier,
  } = req.cookies;

  console.log("Received from Google:", { code, state });
  console.log("Stored cookies:", { storeState, codeVerifier });

  if (!code || !state || !storeState || !codeVerifier || state !== storeState) {
    req.flash(
      "errors",
      "Counld'nt login with Google because of invalid login attempt, Please try Again"
    );
    return res.redirect("/login");
  }

  let tokens;
  try {
    tokens = await google.validateAuthorizationCode(code, codeVerifier);
  } catch (error) {
    req.flash(
      "errors",
      "Counld'nt login with Google because of invalid login attempt, Please try Again"
    );
    return res.redirect("/login");
  }

  console.log("token google:", tokens);

  const claims = decodeIdToken(tokens.idToken());
  console.log("claims", claims);

  const { sub: googleUserId, name, email } = claims;

  let user = await getUserWithOauthId({
    provider: "google",
    email,
  });

  if (user && !user.provideAccountId) {
    await linkUserWithOauth({
      userId: user.id,
      provider: "google",
      providerAccountId: googleUserId,
    });
  }

  if (!user) {
    user = await createUserWithOauth({
      name,
      email,
      provider: "google",
      providerAccountId: googleUserId,
    });
  }

  let userByEmail = await getUserByEmail(claims.email);

  if (!userByEmail) {
    userByEmail = await createUser({
      name: claims.name,
      email: claims.email,
      profilePicture: claims.picture,
    });
  }

  await authenticateUser({
    req,
    res,
    user: userByEmail,
    name: claims.name,
    email: claims.email,
  });

  res.redirect("/");
};

export const getGithubLoginPage = async (req, res) => {
  if (req.user) return res.redirect("/");

  try {
    const state = generateState();
    const url = github.createAuthorizationURL(state, ["user:email"]);

    const cookieConfig = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: OAUTH_EXCHANGE_EXPIRAY,
      sameSite: "lax",
    };

    res.cookie("github_oauth_state", state, cookieConfig);
    res.redirect(url.toString());
  } catch (error) {
    console.error(`Error from get login with google page ${error}`);
  }
};

export const getGithubLoginCallback = async (req, res) => {
  const { code, state } = req.query;
  const { github_oauth_state: storeState } = req.cookies;

  function handleFailedLogin() {
    req.flash(
      "errors",
      "Couldn't login with GitHub due to an invalid login attempt. Please try again."
    );
    return res.redirect("/login");
  }

  if (!code || !state || !storeState || state !== storeState) {
    return handleFailedLogin();
  }

  let tokens;
  try {
    tokens = await github.validateAuthorizationCode(code);
  } catch (error) {
    return handleFailedLogin();
  }

  const githubUserResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokens.accessToken()}`,
    },
  });

  if (!githubUserResponse.ok) return handleFailedLogin();
  const githubUser = await githubUserResponse.json();
  const { id: githubUserId, name, avatar_url } = githubUser;

  const githubEmailResponse = await fetch(
    "https://api.github.com/user/emails",
    {
      headers: {
        Authorization: `Bearer ${tokens.accessToken()}`,
      },
    }
  );

  if (!githubEmailResponse.ok) return handleFailedLogin();
  const emails = await githubEmailResponse.json();
  const primaryEmailObj = emails.find((e) => e.primary && e.verified);
  const email = primaryEmailObj?.email;

  if (!email) return handleFailedLogin();

  let user = await getUserWithOauthId({
    provider: "github",
    email,
  });

  if (user && !user.provideAccountId) {
    await linkUserWithOauth({
      userId: user.id,
      provider: "github",
      provideAccountId: githubUserId,
    });
  }

  if (!user) {
    user = await createUserWithOauth({
      name,
      email,
      provider: "github",
      provideAccountId: githubUserId,
    });
  }

  await authenticateUser({
    req,
    res,
    user,
    name,
    email,
  });

  res.redirect("/");
};

export const getSetPasswordPage = async (req, res) => {
  if (!req.user) return res.redirect("/login");

  try {
    return res.render("auth/set-password", {
      errors: req.flash("errors"),
    });
  } catch (error) {
    console.error(error);
  }
};

export const postSetPassword = async (req, res) => {
  if (!req.user) return res.redirect("/");
  const { data, error } = setPasswordSchema.safeParse(req.body);
  if (error) {
    const errorMessages = error.errors.map((err) => err.message);
    req.flash("errors", errorMessages);
    return res.redirect("/set-password");
  }
  const { newPassword } = data;
  const user = await findByUserId(req.user.id);
  if (user.password) {
    req.flash(
      "erros",
      "You already have your password, instead change your password"
    );
    return res.redirect("/set-password");
  }
  await updateUserPassword({ userId: req.user.id, newPassword });
  return res.redirect("/profile");
};
