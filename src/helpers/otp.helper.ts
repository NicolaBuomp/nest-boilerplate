import * as bcrypt from 'bcrypt';
import * as otpGenerator from 'otp-generator';

export async function generateOtp(): Promise<{
  otp: string;
  hashedOtp: string;
}> {
  const otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    specialChars: false,
    digits: true,
    lowerCaseAlphabets: true,
  });
  const hashedOtp = await bcrypt.hash(otp, 10);
  return { otp, hashedOtp };
}

export async function validateOtp(
  otp: string,
  hashedOtp: string,
): Promise<boolean> {
  return await bcrypt.compare(otp, hashedOtp);
}
