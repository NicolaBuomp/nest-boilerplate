import * as bcrypt from 'bcrypt';

export async function generateOtp(): Promise<{
  otp: string;
  hashedOtp: string;
}> {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const hashedOtp = await bcrypt.hash(otp, 10);
  return { otp, hashedOtp };
}

export async function validateOtp(
  otp: string,
  hashedOtp: string,
): Promise<boolean> {
  return await bcrypt.compare(otp, hashedOtp);
}
