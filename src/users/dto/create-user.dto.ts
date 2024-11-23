import {
  IsNotEmpty,
  IsString,
  IsEmail,
  MinLength,
  Matches,
  IsOptional,
  IsEnum,
} from 'class-validator';
import { Permission } from 'src/auth/permissions.enum';

const passwordRegEx =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/;

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'Email non valida' })
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8, { message: 'La password deve contenere almeno 8 caratteri' })
  @Matches(passwordRegEx, {
    message:
      'La password deve contenere almeno una lettera maiuscola, una minuscola, un numero e un carattere speciale',
  })
  password: string;

  @IsOptional()
  profilePictureUrl?: string;

  @IsOptional()
  @IsString()
  role?: string;

  @IsOptional()
  @IsEnum(Permission, { each: true, message: 'Permesso non valido' })
  permissions?: Permission[];
}
