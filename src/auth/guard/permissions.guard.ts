import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { User } from 'src/users/entities/user.entity';
import { Permission } from '../permissions.enum';
import { PERMISSIONS_KEY } from '../decoretors/permissions.decoretor';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.get<Permission[]>(
      PERMISSIONS_KEY,
      context.getHandler(),
    );
    if (!requiredPermissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user: User = request.user;

    const hasPermission = requiredPermissions.every((permission) =>
      user.permissions?.includes(permission),
    );

    if (!hasPermission) {
      throw new ForbiddenException(
        `Non sei autorizzato a questa risorsa. Permessi richiesti: ${requiredPermissions.join(', ')}`,
      );
    }

    return true;
  }
}
