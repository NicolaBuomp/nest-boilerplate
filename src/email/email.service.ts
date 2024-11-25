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

  async sendVerificationOtp(to: string, name: string, otp: string) {
    const mailOptions = {
      from: `"Nest Boilerplate" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'Verifica la tua email',
      html: `
      <p>Ciao ${name},</p>
      <p>Grazie per esserti registrato. Usa il seguente codice OTP per verificare il tuo indirizzo email: <strong>${otp}</strong></p>
      <p>Se non hai richiesto questa email, ti preghiamo di ignorarla. Se continui a ricevere queste email, contatta il nostro supporto.</p>
    `,
    };

    try {
      this.logger.log(`Tentativo di invio OTP di verifica a ${to}`);
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`OTP di verifica inviato con successo: ${info.response}`);
    } catch (error) {
      this.logger.error(`Errore durante l'invio dell'OTP a ${to}`, error.stack);
      throw new Error(
        'Errore durante l’invio della email di verifica. Riprova più tardi.',
      );
    }
  }

  async sendPasswordResetEmail(to: string, name: string, token: string) {
    const resetUrl = `${process.env.APP_URL}/auth/reset-password?token=${token}`;
    const mailOptions = {
      from: `"Nest Boilerplate" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'Reset della Password',
      html: `
      <p>Ciao ${name},</p>
      <p>Hai richiesto un reset della password. Clicca sul seguente link per reimpostare la tua password: <a href="${resetUrl}">Reset Password</a></p>
      <p>Se non hai richiesto questa email, ti preghiamo di ignorarla. Se continui a ricevere queste email, contatta il nostro supporto.</p>
    `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email di reset password inviata a ${to}`);
    } catch (error) {
      this.logger.error(
        `Errore durante l'invio dell'email a ${to}`,
        error.stack,
      );
      throw new Error(
        'Errore durante l’invio dell’email di reset della password. Riprova più tardi.',
      );
    }
  }

  async sendAccountBlockedEmail(to: string, name: string) {
    const mailOptions = {
      from: `"Nest Boilerplate" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'Account bloccato per troppi tentativi di accesso',
      html: `
    <p>Ciao ${name},</p>
    <p>Il tuo account è stato bloccato a causa di troppi tentativi di accesso falliti. Ti preghiamo di attendere 30 minuti e poi potrai riprovare.</p>
    <p>Se non sei stato tu, ti consigliamo di contattare il nostro supporto.</p>
  `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email di blocco account inviata a ${to}`);
    } catch (error) {
      this.logger.error(
        `Errore durante l'invio dell'email di blocco a ${to}`,
        error.stack,
      );
      throw new Error(
        'Errore durante l’invio della notifica di blocco account.',
      );
    }
  }
}
