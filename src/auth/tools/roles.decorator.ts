import { SetMetadata } from '@nestjs/common';

/**
 * Allow only specified roles to access a specific route
 * @param roles
 * @constructor
 */
export const Roles = (...roles: string[]) => SetMetadata('roles', roles);
