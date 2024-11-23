import { Controller, Post, Body, UseGuards } from '@nestjs/common';
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
