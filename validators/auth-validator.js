import z from "zod";

export const loginUserSchema = z.object({
  email: z
    .string()
    .trim()
    .email()
    .min(3, { message: "Email must be aleast 3 characters long." })
    .max(100, { message: "Email must be less then 100 characters." }),
  password: z
    .string()
    .min(6, { message: "Password must be aleast 3 characters long." })
    .max(100, { message: "Password must be less then 100 characters." }),
});

export const registerUserSchema = loginUserSchema.extend({
  name: z
    .string()
    .trim()
    .min(3, { message: "Name must be aleast 3 characters long." })
    .max(100, { message: "Name must be less then 100 characters." }),
});
