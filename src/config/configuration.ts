export const configuration = () => {
  return {
    environment: process.env.NODE_ENV,
    port: process.env.PORT,
    host: process.env.HOST,
    dbUri: process.env.DB_URI,
    jwtSecret: process.env.TOKEN_SECRET,
    jwtExpiration: process.env.JWT_EXPIRATION,
    encryptJwtSecret: process.env.ENCRYPT_JWT_SECRET,
    ip: process.env.IP,
  };
};
