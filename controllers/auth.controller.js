export const getRegistrationPage = (req, res) => {
  return res.render("./auth/register");
};

export const getLoginPage = (req, res) => {
  return res.render("./auth/login");
};

export const postLogin = (req, res) => {
  //   res.setHeader("Set-Cookie", "isLoggedIn=true; path=/;");
  res.cookie("isLoggedIn", true);
  res.redirect("/");
};
