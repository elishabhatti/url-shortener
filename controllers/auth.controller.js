import { getUserByEmail, createUser, comparePassword, hashPassword } from "../services/auth.services.js";

export const getRegistrationPage = (req, res) => {
  return res.render("./auth/register");
};

export const getLoginPage = (req, res) => {
  return res.render("./auth/login");
};

export const postLogin = async (req, res) => {
  const { email, password } = req.body;

  const userExists = await getUserByEmail(email);
  console.log("User Exisits", userExists);

  if (!userExists) return res.redirect("/login");
  if (userExists.password !== password) return res.redirect("/login");

  res.cookie("isLoggedIn", true);
  res.redirect("/");
};

export const postRegister = async (req, res) => {
  const { name, email, password } = req.body;

  const userExists = await getUserByEmail(email);
  console.log("User Exisits", userExists);

  const hashedPassoword = await hashPassword(password)

  if (userExists) return res.redirect("/register");
  const [user] = await createUser({ name, email, password : hashedPassoword });
  console.log(user);

  res.redirect("/login");
};
