import fs from "fs/promises";
import path from "path";

const DATA_FILE = path.join("data", "links.json");

export const loadLinks = async () => {
  try {
    const data = await fs.readFile(DATA_FILE, "utf-8");
    return JSON.parse(data);
  } catch (error) {
    if (error.code === "ENOENT") {
      await fs.writeFile(DATA_FILE, JSON.stringify({}), "utf-8");
      return {};
    }
    throw error;
  }
};

export const saveLinks = async (links) => {
  await fs.writeFile(DATA_FILE, JSON.stringify(links, null, 2), "utf-8");
};
