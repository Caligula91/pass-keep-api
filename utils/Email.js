const nodemailer = require('nodemailer');
const pug = require('pug');
const { htmlToText } = require('html-to-text');

module.exports = class Email {
  // data contains ip info and guard code
  constructor(user, url, data) {
    this.to = user.email;
    this.firstName = user.name.split(' ')[0];
    this.url = url;
    this.from = `PassKeep <${process.env.EMAIL_FROM}>`;
    this.data = data;
  }

  newTransport() {
    if (process.env.NODE_ENV === 'production') {
      // SENDGRID
      return nodemailer.createTransport({
        service: 'SendGrid',
        auth: {
          user: process.env.SENDGRID_USERNAME,
          pass: process.env.SENDGRID_PASSWORD,
        },
      });
    }
    // MAILTRAP
    return nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
    });
  }

  /**
   * SEND EMAIL
   */
  async send(template, subject) {
    // 1) Render HTML based on a pug template
    const html = pug.renderFile(`${__dirname}/../views/email/${template}.pug`, {
      firstName: this.firstName,
      url: this.url,
      data: this.data,
      subject,
    });

    // 2) Define email options
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
      text: htmlToText(html),
    };

    // 3) Create a transport and send email
    await this.newTransport().sendMail(mailOptions);
  }

  async sendWelcome() {
    await this.send('welcome', 'Welcome to PassKeep');
  }

  async sendPasswordReset() {
    await this.send('passwordReset', 'Password Reset (valid 10 minutes)');
  }

  async sendPasswordResetRequest() {
    await this.send(
      'passwordResetRequest',
      'Password Reset (valid 10 minutes)'
    );
  }

  async sendConfirmation() {
    await this.send(
      'emailConfirmation',
      'Email Confirmation (valid 10 minutes)'
    );
  }

  async sendWelcomeBack() {
    await this.send('welcomeBack', 'Welcome Back');
  }

  async sendGuardCode() {
    await this.send('guardCode', 'Access from new computer');
  }
};
