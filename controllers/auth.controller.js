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
  confirmNewUserPassword,
} from "../services/auth.services.js";
import {
  loginUserSchema,
  registerUserSchema,
  verifyEmailSchema,
  verifyPasswordSchema,
  verifyUserSchema,
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
    return res.redirect("/login");
  }

  const { email, password } = data;
  const userExists = await getUserByEmail(email);

  if (!userExists) {
    req.flash("errors", "Invalid Password");
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

// getProfilePage
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

  await updateUserByName({ userId: req.user.id, name: data.name });
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

  return res.redirect("/profile");
};
