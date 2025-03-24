export const getRegistrationPage = (req, res) => {
  return res.render("./auth/register");
};

export const getLoginPage = (req, res) => {
  return res.render("./auth/login");
};
