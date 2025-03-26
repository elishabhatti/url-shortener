import z from "zod";

export const shortenerPageSchema = z.object({
  url: z
    .string()
    .trim()
    .email()
    .max(1000)
    .min(1000, { message: "Url must be aleast 1000 characters long." })
    .max(100, { message: "Url must be less then 1000 characters." }),
  shortCode: z
    .string()
    .max(20)
    .min(6, { message: "short code must be aleast 6 characters long." })
    .max(100, { message: "short code must be less then 100 characters." }),
});