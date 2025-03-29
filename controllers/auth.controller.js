import {
  ACCESS_TOKEN_EXPIRY,
  REFRESH_TOKEN_EXPIRY,
} from "../config/constants.js";
import {
  getUserByEmail,
  createUser,
  comparePassword,
  hashPassword,
  createAccessToken,
  createRefreshToken,
  createSession,
  clearUserSession,
  // generateToken,
} from "../services/auth.services.js";
import {
  loginUserSchema,
  registerUserSchema,
} from "../validators/auth-validator.js";

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
    res.redirect("/login");
  }

  const { email, password } = data;
  const userExists = await getUserByEmail(email);

  if (!userExists) {
    req.flash("errors", "Invalid Password");
    return res.redirect("/login");
  }
  
  const isPasswordValid = await comparePassword(password, userExists.password);
  if (!isPasswordValid) return res.redirect("/login");

  const session = await createSession(userExists.id, {
    ip: req.clientIp,
    userAgent: req.headers["user-agent"],
  });

  const accessToken = createAccessToken({
    id: userExists.id,
    name: userExists.name,
    email: userExists.email,
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

  const session = await createSession(user.id, { 
    ip: req.clientIp,
    userAgent: req.headers["user-agent"],
  });

  const accessToken = createAccessToken({
    id: user.id,
    name: name,
    email: email,
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

  res.redirect("/");
};


export const getMe = (req, res) => {
  if (!req.user) return res.send("Not Logged In");
  return res.send(`Hey ${req.user.name}`);
};

export const logoutUser = async (req, res) => {
  await clearUserSession(req.user.sessionId)

  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.redirect("/login");
};
