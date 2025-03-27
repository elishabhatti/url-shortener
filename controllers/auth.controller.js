import {
  getUserByEmail,
  createUser,
  comparePassword,
  hashPassword,
  generateToken,
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
  const { email, password } = req.body;

  const userExists = await getUserByEmail(email);
  if (!userExists) {
    req.flash("errors", "Invalid Password");
    return res.redirect("/login");
  }

  const isPasswordValid = await comparePassword(password, userExists.password);
  if (!isPasswordValid) return res.redirect("/login");

  const token = generateToken({
    id: userExists.id,
    name: userExists.name,
    password: userExists.password,
  });
  res.cookie("access_token", token);
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

  // Ensure 'data' contains the expected values
  const { name, email, password } = data;

  const userExists = await getUserByEmail(email);
  if (userExists) {
    req.flash("errors", "User already exists");
    return res.redirect("/register");
  }

  const hashedPassword = await hashPassword(password);
  await createUser({ name, email, password: hashedPassword });

  res.redirect("/login");
};


export const getMe = (req, res) => {
  if (!req.user) return res.send("Not Logged In");
  return res.send(`Hey ${req.user.name}`);
};

export const logoutUser = (req, res) => {
  res.clearCookie("access_token");
  res.redirect("/login");
};
