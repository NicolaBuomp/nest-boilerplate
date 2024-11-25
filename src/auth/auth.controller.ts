import { Controller, Post, Body, UseGuards, Get, Query } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { JwtAuthGuard } from './guard/auth.guard';
import { GetUser } from './decoretors/user.decoretor';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    return await this.authService.register(createUserDto);
  }

  @Get('verify-email')
  async verifyEmail(@Query('email') email: string, @Query('otp') otp: string) {
    try {
      await this.authService.verifyOtp(email, otp);
      return { success: true, message: 'Email verificata con successo' };
    } catch (e) {
      return { success: false, message: e.message };
    }
  }

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

  @Post('login')
  async login(@Body() loginDto: { email: string; password: string }) {
    return await this.authService.login(loginDto.email, loginDto.password);
  }

  @Post('refresh')
  async refresh(@Body() refreshDto: { refresh_token: string }) {
    return await this.authService.refreshAccessToken(refreshDto.refresh_token);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@GetUser('id') userId: string) {
    return await this.authService.logout(userId);
  }
}
