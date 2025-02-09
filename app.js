import express from "express";
import { shortenedRoutes } from "./routes/shortener.routes.js";

const app = express();
const PORT = 3000;
app.set("view engine", "ejs");

app.use(express.json());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(shortenedRoutes);

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
