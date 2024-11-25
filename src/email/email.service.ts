import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 587,
      secure: false,
      auth: {
        user: 'apikey',
        pass: process.env.SENDGRID_API_KEY,
      },
    });
  }

  async sendVerificationOtp(to: string, otp: string) {
    const mailOptions = {
      from: `"Nest Boilerplate" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'Verifica la tua email',
      html: `<p>Grazie per esserti registrato. Usa il seguente codice OTP per verificare il tuo indirizzo email: <strong>${otp}</strong></p>`,
    };

    try {
      this.logger.log(`Tentativo di invio OTP di verifica a ${to}`);
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`OTP di verifica inviato con successo: ${info.response}`);
    } catch (error) {
      this.logger.error(`Errore durante l'invio dell'OTP a ${to}`, error.stack);
    }
  }

  async sendVerificationEmail(to: string, token: string) {
    const verificationUrl = `${process.env.APP_URL}/verify-email?token=${token}`;
    const mailOptions = {
      from: `"Nest Boilerplate" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'Verifica la tua email',
      html: `<p>Grazie per esserti registrato. Clicca sul seguente link per verificare il tuo indirizzo email: <a href="${verificationUrl}">Verifica Email</a></p>`,
    };

    try {
      this.logger.log(`Tentativo di invio email di verifica a ${to}`);
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(
        `Email di verifica inviata con successo: ${info.response}`,
      );
    } catch (error) {
      this.logger.error(
        `Errore durante l'invio dell'email a ${to}`,
        error.stack,
      );
    }
  }

  async sendPasswordResetEmail(to: string, token: string) {
    const resetUrl = `${process.env.APP_URL}/auth/reset-password?token=${token}`;
    const mailOptions = {
      from: `"Nest Boilerplate" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'Reset della Password',
      html: `<p>Hai richiesto un reset della password. Clicca sul seguente link per reimpostare la tua password: <a href="${resetUrl}">Reset Password</a></p>`,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email di reset password inviata a ${to}`);
    } catch (error) {
      this.logger.error(
        `Errore durante l'invio dell'email a ${to}`,
        error.stack,
      );
    }
  }
}
