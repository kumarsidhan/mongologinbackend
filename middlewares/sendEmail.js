import nodemailer from 'nodemailer';
// import config from 'config';

// const emailConfig = config.get('emailService');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'kumarsidhan@gmail.com',
    pass: 'mioo xnmf mloq wxbd',
  },
});

export const sendOTP = async (to, otp) => {
  const mailOptions = {
    from: 'kumarsidhan@gmail.com',
    to,
    subject: 'Password Reset OTP',
    text: `Your OTP for password reset is: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('OTP sent');
  } catch (error) {
    console.error('Error sending OTP:', error);
  }
};
