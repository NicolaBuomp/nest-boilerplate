import { Permission } from 'src/auth/permissions.enum';
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255, nullable: false })
  name: string;

  @Column({ type: 'varchar', unique: true, nullable: false })
  email: string;

  @Column({ type: 'varchar', nullable: false })
  password: string;

  @Column({ type: 'varchar', nullable: true })
  phone: string;

  @Column({ type: 'varchar', nullable: true, default: 'user' })
  role: string;

  @Column('simple-array', { nullable: true })
  permissions: Permission[];

  @Column({ type: 'varchar', nullable: true })
  profilePictureUrl?: string;

  @Column({ type: 'boolean', default: false })
  isEmailVerified: boolean;

  @Column({ type: 'text', nullable: true })
  refreshToken?: string;

  @Column({ type: 'varchar', nullable: true })
  verificationOtp?: string;

  @Column({ type: 'timestamp', nullable: true })
  otpExpiry?: Date;

  @Column({ type: 'int', nullable: true })
  otpAttempts?: number;

  @Column({ type: 'int', default: 0 })
  otpRequestCount?: number;

  @Column({ type: 'timestamp', nullable: true })
  otpRequestResetTime?: Date;

  @Column({ type: 'timestamp', nullable: true })
  lockedUntil?: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
