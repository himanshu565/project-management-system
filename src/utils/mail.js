import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendEmail = async (options) => {
    const mailGenerator = new Mailgen({
        theme: "default",
        product: {
            name: "Task Manager",
            link: "https://taskmainagelink.com",
        },
})
    const emailTextual = mailGenerator.generatePlaintext(options.mailgencontent)
    const emailHtml = mailGenerator.generateHtml(options.mailgencontent)


    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: process.env.MAILTRAP_SMTP_PORT,
        auth: {
            user:process.env.MAILTRAP_SMTP_USER,
            password:process.env.MAILTRAP_SMTP_PASS,
    }})
    const mail = {
        from: "mail.taskmanager@example.com",
        to: options.to,
        subject: options.subject,
        text: emailTextual,
        html: emailHtml,

    }
    try{
        await transporter.sendEmail(mail);

    }catch(error){
        console.error("email service failed this mught ahve failed due to crediantials make sure u have provided  the mailtrap crediantials in the env file");
        console.log(error);

    }
};

const EmailverificationMailgenCContent = (username ,verificationUrl) => {
    return {
        body: {
            name: username,
            intro: "welcome to the team",
            action: {
                instructions: "To verifiy click on the button or link ",
                button : {
                color: '#22BC66', // Optional action button color
                text: 'Confirm your account',
                link: 'verificationUrl' 
            },
            },
            outro: "need help , or have questions ? just reply to this email",


        }
    };
};
const ForgotPasswordMailgenContent = (username ,ForgotPasswordUrl) => {
    return {
        body: {
            name: username,
            intro: " we got a request to reset your password",
            action: {
                instructions: "To reset your password click the button below.",
                button : {
                color: '#22BC66', // Optional action button color
                text: 'Confirm your account',
                link: 'ForgotPasswordUrl' 
            },
            },
            outro: "need help , or have questions ? just reply to this email",


        }
    };
};
export { EmailverificationMailgenCContent , ForgotPasswordMailgenContent ,sendEmail}