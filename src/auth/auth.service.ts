import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import { ConfigService } from '@nestjs/config';
import { EmailService } from 'src/email/email.service';
import { generateOtp, validateOtp } from 'src/helpers/otp.helper';
import { ERROR_MESSAGES } from 'src/helpers/error-message.helper';
import { ResetPasswordDto } from 'src/users/dto/reset-password.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  async register(createUserDto: CreateUserDto): Promise<User> {
    const existingUser = await this.usersService.findOneByEmail(
      createUserDto.email,
    );
    if (existingUser && existingUser.isEmailVerified) {
      throw new UnauthorizedException(
        `Email già in uso. Se hai già registrato un account, accedi oppure verifica l'email utilizzando il link ricevuto.`,
      );
    } else if (existingUser && !existingUser.isEmailVerified) {
      throw new UnauthorizedException(
        'Email già in uso, ma non verificata! Clicca qui per ricevere un nuovo codice di verifica.',
      );
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const user = await this.usersService.create({
      ...createUserDto,
      password: hashedPassword,
    });

    const { otp, hashedOtp } = await generateOtp();
    user.verificationOtp = hashedOtp;
    user.otpExpiry = new Date(Date.now() + 15 * 60 * 1000);
    await this.usersService.update(user.id, {
      verificationOtp: user.verificationOtp,
      otpExpiry: user.otpExpiry,
      otpAttempts: 0,
      otpRequestCount: 0,
    });

    await this.emailService.sendVerificationOtp(user.email, user.name, otp);

    return user;
  }

  async verifyOtp(email: string, otp: string): Promise<void> {
    const user = await this.usersService.findOneByEmail(email);
    if (!user) {
      throw new UnauthorizedException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    // Verifica se l'account è bloccato
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new UnauthorizedException(
        `${ERROR_MESSAGES.ACCOUNT_LOCKED} Riprova tra ${Math.ceil(
          (user.lockedUntil.getTime() - new Date().getTime()) / 60000,
        )} minuti.`,
      );
    }

    if (user.otpAttempts >= 3) {
      // Blocca l'account per 30 minuti
      user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
      await this.usersService.update(user.id, {
        lockedUntil: user.lockedUntil,
      });

      // Invia una notifica all'utente
      await this.emailService.sendAccountBlockedEmail(user.email, user.name);

      throw new UnauthorizedException(ERROR_MESSAGES.ACCOUNT_LOCKED);
    }

    if (
      !user.verificationOtp ||
      !user.otpExpiry ||
      user.otpExpiry < new Date()
    ) {
      throw new BadRequestException(ERROR_MESSAGES.OTP_EXPIRED);
    }

    const isOtpValid = await validateOtp(otp, user.verificationOtp);
    if (!isOtpValid) {
      user.otpAttempts += 1;
      await this.usersService.update(user.id, {
        otpAttempts: user.otpAttempts,
      });
      throw new UnauthorizedException(ERROR_MESSAGES.INVALID_OTP);
    }

    user.isEmailVerified = true;
    user.verificationOtp = null;
    user.otpExpiry = null;
    user.otpAttempts = 0;
    user.lockedUntil = null; // Sblocca l'account se la verifica è riuscita
    await this.usersService.update(user.id, {
      isEmailVerified: true,
      verificationOtp: null,
      otpExpiry: null,
      otpAttempts: 0,
      lockedUntil: null,
    });
  }

  async login(
    email: string,
    password: string,
  ): Promise<{ access_token: string; refresh_token: string }> {
    const user = await this.usersService.findOneByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException(
        'Email o password non corretti. Verifica i dati inseriti e riprova.',
      );
    }

    if (!user.isEmailVerified) {
      throw new UnauthorizedException(
        'Questo account non è ancora verificato. Clicca qui per inviare un nuovo codice OTP alla tua mail e verificare il tuo account!',
      );
    }

    const payload = { email: user.email, sub: user.id };

    const secret = this.configService.get<string>('JWT_SECRET');

    const refreshToken = this.jwtService.sign(payload, {
      secret,
      expiresIn: '7d',
    });

    user.refreshToken = await bcrypt.hash(refreshToken, 10);
    await this.usersService.update(user.id, {
      refreshToken: user.refreshToken,
    });

    return {
      access_token: this.jwtService.sign(payload, {
        secret,
        expiresIn: '15m',
      }),
      refresh_token: refreshToken,
    };
  }

  async refreshAccessToken(
    refreshToken: string,
  ): Promise<{ access_token: string }> {
    try {
      const secret = this.configService.get<string>('JWT_SECRET');
      const payload = this.jwtService.verify(refreshToken, { secret });

      const user = await this.usersService.findOne(payload.sub);
      if (!user || !(await bcrypt.compare(refreshToken, user.refreshToken))) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const newPayload = { email: payload.email, sub: payload.sub };
      const newAccessToken = this.jwtService.sign(newPayload, {
        secret,
        expiresIn: '15m',
      });

      return { access_token: newAccessToken };
    } catch (e) {
      this.logger.error('Invalid refresh token', e.stack);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(userId: string): Promise<void> {
    await this.usersService.update(userId, { refreshToken: null });
  }

  async resendVerificationEmail(email: string): Promise<void> {
    const user = await this.usersService.findOneByEmail(email);
    if (!user) {
      throw new UnauthorizedException(ERROR_MESSAGES.USER_NOT_FOUND);
    }
    if (user.isEmailVerified) {
      throw new UnauthorizedException(ERROR_MESSAGES.EMAIL_ALREADY_VERIFIED);
    }

    const now = new Date();
    if (user.otpRequestResetTime && user.otpRequestResetTime < now) {
      user.otpRequestCount = 0;
    }

    if (user.otpRequestCount >= 3) {
      throw new BadRequestException(ERROR_MESSAGES.TOO_MANY_OTP_REQUESTS);
    }

    user.otpRequestCount += 1;
    user.otpRequestResetTime = new Date(now.getTime() + 60 * 60 * 1000);

    const { otp, hashedOtp } = await generateOtp();
    user.verificationOtp = hashedOtp;
    user.otpExpiry = new Date(Date.now() + 15 * 60 * 1000);
    user.otpAttempts = 0;
    await this.usersService.update(user.id, {
      verificationOtp: user.verificationOtp,
      otpExpiry: user.otpExpiry,
      otpAttempts: user.otpAttempts,
      otpRequestCount: user.otpRequestCount,
      otpRequestResetTime: user.otpRequestResetTime,
    });

    await this.emailService.sendVerificationOtp(user.email, user.name, otp);
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const { token, newPassword } = resetPasswordDto;

    try {
      const secret = this.configService.get<string>('JWT_SECRET');
      const payload = this.jwtService.verify(token, { secret });

      const user = await this.usersService.findOneByEmail(payload.email);
      if (!user) {
        throw new UnauthorizedException('Utente non trovato.');
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await this.usersService.update(user.id, { password: hashedPassword });
    } catch (e) {
      this.logger.error('Errore durante il reset della password', e.stack);
      throw new UnauthorizedException(
        'Token non valido o scaduto. Richiedi nuovamente il reset della password.',
      );
    }
  }
}
