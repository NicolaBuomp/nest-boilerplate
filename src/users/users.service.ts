import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { EntityNotFoundException } from 'src/filters/entity-not-found.exception';
import { Permission } from 'src/auth/permissions.enum';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  private assignPermissions(role: string): Permission[] {
    switch (role) {
      case 'admin':
        return [
          Permission.CREATE_RESOURCE,
          Permission.UPDATE_RESOURCE,
          Permission.DELETE_RESOURCE,
          Permission.VIEW_RESOURCE,
          Permission.MANAGE_USERS,
          Permission.VIEW_ANALYTICS,
        ];
      case 'user':
        return [Permission.VIEW_RESOURCE];
      default:
        return [];
    }
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const user = this.userRepository.create({
      ...createUserDto,
      permissions: this.assignPermissions(createUserDto.role),
    });
    return this.userRepository.save(user);
  }

  async findAll(): Promise<User[]> {
    return await this.userRepository.find();
  }

  async findOneByEmail(email: string): Promise<User | null> {
    const user = await this.userRepository.findOne({ where: { email } });
    return user ?? null;
  }

  async findOne(id: string): Promise<User> {
    const user = await this.userRepository.findOneBy({ id });
    if (!user) {
      throw new EntityNotFoundException('Utente', id);
    }
    return user;
  }

  async update(id: string, updateData: Partial<User>): Promise<User> {
    const user = await this.findOne(id);
    Object.assign(user, updateData);
    return this.userRepository.save(user);
  }
}
