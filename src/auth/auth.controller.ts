import { Controller, Post, Body, UseGuards, Get, Query } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { JwtAuthGuard } from './guard/auth.guard';
import { GetUser } from './decoretors/user.decoretor';
import { ResetPasswordDto } from 'src/users/dto/reset-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // Limita a 5 richieste per minuto
  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    return await this.authService.register(createUserDto);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // Limita a 5 richieste per minuto
  @Get('verify-email')
  async verifyEmail(@Query('email') email: string, @Query('otp') otp: string) {
    try {
      await this.authService.verifyOtp(email, otp);
      return { success: true, message: 'Email verificata con successo' };
    } catch (e) {
      return { success: false, message: e.message };
    }
  }

  @Throttle({ default: { limit: 5, ttl: 36000 } }) // Limita a 3 richieste per ora
  @Post('resend-verification-email')
  async resendVerificationEmail(@Body('email') email: string) {
    try {
      await this.authService.resendVerificationEmail(email);
      return {
        success: true,
        message: 'Email di verifica reinviata con successo',
      };
    } catch (e) {
      return { success: false, message: e.message };
    }
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // Limita a 5 richieste per minuto
  @Post('login')
  async login(@Body() loginDto: { email: string; password: string }) {
    return await this.authService.login(loginDto.email, loginDto.password);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // Limita a 5 richieste per minuto
  @Post('refresh')
  async refresh(@Body() refreshDto: { refresh_token: string }) {
    return await this.authService.refreshAccessToken(refreshDto.refresh_token);
  }

  @Throttle({ default: { limit: 2, ttl: 36000 } })
  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    try {
      await this.authService.resetPassword(resetPasswordDto);
      return {
        success: true,
        message: 'Password reimpostata con successo.',
      };
    } catch (e) {
      return {
        success: false,
        message: e.message,
      };
    }
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@GetUser('id') userId: string) {
    return await this.authService.logout(userId);
  }
}
