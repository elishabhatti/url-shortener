import z from "zod";

// Reusable name schema
const nameSchema = z
  .string()
  .trim()
  .min(3, { message: "Name must be at least 3 characters long." })
  .max(100, { message: "Name must be less than 100 characters." });

export const loginUserSchema = z.object({
  email: z
    .string()
    .trim()
    .email()
    .min(3, { message: "Email must be at least 3 characters long." })
    .max(100, { message: "Email must be less than 100 characters." }),
  password: z
    .string()
    .min(6, { message: "Password must be at least 6 characters long." })
    .max(100, { message: "Password must be less than 100 characters." }),
});

export const registerUserSchema = loginUserSchema.extend({
  name: nameSchema,
});

export const verifyUserSchema = z.object({
  name: nameSchema,
});

export const verifyEmailSchema = z.object({
  token: z.string().trim().length(8),
  email: z.string().trim().email(),
});
