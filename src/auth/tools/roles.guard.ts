import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());

    if (!roles) {
      return true;
    }

    const isPublic = this.reflector.getAllAndOverride<boolean>('public', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!roles || isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    let isAllowed = false;

    roles.forEach((role) => {
      if (user.role === role) {
        isAllowed = true;
      }
    });

    if (!isAllowed) throw new ForbiddenException();
    return isAllowed;
  }
}
