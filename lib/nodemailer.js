import nodemailer from "nodemailer";

const testAccount = await nodemailer.createTestAccount();

const transporter = nodemailer.createTransport({
  host: "smtp.ethereal.email",
  port: 587,
  secure: false,
  auth: {
    user: "merritt.huels@ethereal.email",
    pass: "Qvk2GpcJPA8WPUyRqw",
  },
});

export const sendEmail = async ({ to, subject, html }) => {
  transporter.sendMail({
    from: `URL SHORTENER < ${testAccount.user} >`,
    to,
    subject,
    html,
  });
};
