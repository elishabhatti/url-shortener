import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

export const sendEmail = async ({ to, subject, html }) => {
  try {
    const { data, error } = await resend.emails.send({
      from: "Website <website@resend.dev>",
      to,
      subject,
      html,
    });

    if (error) {
      return console.error("Errorr",error);
    } else {
      console.log(data);
    }
  } catch (error) {
    console.error("Try Catch Error",error);
  }
};
