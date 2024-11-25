import { IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';

const passwordRegEx =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/;

export class ResetPasswordDto {
  @IsNotEmpty()
  @IsString()
  token: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8, { message: 'La password deve contenere almeno 8 caratteri' })
  @Matches(passwordRegEx, {
    message:
      'La password deve contenere almeno una lettera maiuscola, una minuscola, un numero e un carattere speciale',
  })
  newPassword: string;
}
