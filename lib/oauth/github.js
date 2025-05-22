import { GitHub } from "arctic";
import { env } from "../../config/env.js";

export const github = new GitHub(
  env.GITHUB_CLIENT_ID,
  env.GITHUB_CLIENT_SECRET,
  "http://localhost:3000/github/callback"
);
