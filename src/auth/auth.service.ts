import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(createUserDto: CreateUserDto): Promise<User> {
    const existingUser = await this.usersService.findOneByEmail(
      createUserDto.email,
    );
    if (existingUser) {
      throw new UnauthorizedException('Email già in uso');
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    return await this.usersService.create({
      ...createUserDto,
      password: hashedPassword,
    });
  }

  async login(
    email: string,
    password: string,
  ): Promise<{ access_token: string; refresh_token: string }> {
    const user = await this.usersService.findOneByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
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
}
