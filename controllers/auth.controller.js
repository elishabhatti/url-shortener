import {
  getUserByEmail,
  createUser,
  comparePassword,
  hashPassword,
  generateToken,
} from "../services/auth.services.js";

export const getRegistrationPage = (req, res) => {
  return res.render("./auth/register");
};

export const getLoginPage = (req, res) => {
  return res.render("./auth/login");
};

export const postLogin = async (req, res) => {
  const { email, password } = req.body;

  const userExists = await getUserByEmail(email);
  if (!userExists) return res.redirect("/login");

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
  const { name, email, password } = req.body;

  const userExists = await getUserByEmail(email);
  if (userExists) return res.redirect("/register");

  const hashedPassword = await hashPassword(password);
  await createUser({ name, email, password: hashedPassword });

  res.redirect("/login");
};

export const getMe = (req, res) => {
  if (!req.user) return res.send("Not Logged In");;
  return res.send(`Hey ${req.user.name}`)
};
