import { verifyJwtToken } from "../services/auth.services.js";

export const verifyAuthentication = async (req, res, next) => {
  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

  req.user = null;

  if (!accessToken && !refreshToken) {
    return next();
  }

  if (accessToken) {
    try {
      const decodedToken = verifyJwtToken(accessToken);
      req.user = decodedToken;
      return next();
    } catch (error) {
      console.error("Access token invalid:", error.message);
    }
  }

  if (refreshToken) {
    try {
      const { newAccessToken, newRefreshToken, user } = await refreshToken(
        refreshToken
      );
      req.user = user;

      const baseConfig = { httpOnly: true, secure: true };

      res.cookie("access_token", newAccessToken, {
        ...baseConfig,
        maxAge: ACCESS_TOKEN_EXPIRY,
      });

      res.cookie("refresh_token", newRefreshToken, {
        ...baseConfig,
        maxAge: REFRESH_TOKEN_EXPIRY,
      });

      return next();
    } catch (error) {
      console.error("Refresh token invalid:", error.message);
    }
  }

  return next();
};
