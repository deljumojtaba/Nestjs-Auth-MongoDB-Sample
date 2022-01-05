import * as Joi from 'joi';

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),
  PORT: Joi.number().default(3000),
  HOST: Joi.string(),
  DB_URI: Joi.string(),
  IP: Joi.string(),
  TOKEN_SECRET: Joi.string(),
  JWT_EXPIRATION: Joi.string(),
  ENCRYPT_JWT_SECRET: Joi.string(),
});
