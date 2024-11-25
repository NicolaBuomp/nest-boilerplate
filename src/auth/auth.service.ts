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

    await this.emailService.sendVerificationOtp(user.email, otp);

    return user;
  }

  async verifyOtp(email: string, otp: string): Promise<void> {
    const user = await this.usersService.findOneByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Utente non trovato');
    }
    if (user.otpAttempts >= 3) {
      throw new UnauthorizedException(
        'Numero massimo di tentativi superato. Richiedi un nuovo codice OTP.',
      );
    }
    if (
      !user.verificationOtp ||
      !user.otpExpiry ||
      user.otpExpiry < new Date()
    ) {
      throw new BadRequestException('OTP scaduto, richiedi un nuovo codice');
    }
    const isOtpValid = await validateOtp(otp, user.verificationOtp);
    if (!isOtpValid) {
      user.otpAttempts += 1;
      await this.usersService.update(user.id, {
        otpAttempts: user.otpAttempts,
      });
      throw new UnauthorizedException('OTP non valido');
    }

    user.isEmailVerified = true;
    user.verificationOtp = null;
    user.otpExpiry = null;
    user.otpAttempts = 0;
    await this.usersService.update(user.id, {
      isEmailVerified: true,
      verificationOtp: null,
      otpExpiry: null,
      otpAttempts: 0,
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
      throw new UnauthorizedException('Utente non trovato');
    }
    if (user.isEmailVerified) {
      throw new UnauthorizedException('Email già verificata');
    }

    const now = new Date();
    if (user.otpRequestResetTime && user.otpRequestResetTime < now) {
      user.otpRequestCount = 0;
    }

    if (user.otpRequestCount >= 3) {
      throw new BadRequestException(
        `Hai superato il numero massimo di richieste OTP. Attendi un'ora prima di richiedere un nuovo codice.`,
      );
    }

    user.otpRequestCount += 1;
    user.otpRequestResetTime = new Date(now.getTime() + 60 * 60 * 1000); // Reset dopo un'ora

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

    await this.emailService.sendVerificationOtp(user.email, otp);
  }
}
