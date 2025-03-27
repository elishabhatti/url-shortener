import z from "zod";

export const shortenerSchema = z.object({
  url: z
    .string({ required_error: "Url is required" })
    .trim()
    .url({ message: "Please enter a valid Url" })
    .max(1024, { message: "Url cannot be longer then 1024 characters" }),
  shortCode: z
    .string({ required_error: "Url is required" })
    .trim()
    .min(2, { message: "Short Code cannot be less then 2 characters" })
    .max(20, { message: "Short Code cannot be longer then 20 characters" }),
});
