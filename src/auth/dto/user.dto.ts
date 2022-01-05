import { ApiProperty } from "@nestjs/swagger";
import { Expose } from "class-transformer";
import { IsString, MinLength, MaxLength, IsEmail } from "class-validator";

export class UserDto {
  @Expose()
  @IsString()
  @ApiProperty({
    description: "user full name",
    type: "string",
    default: "naap user",
  })
  fullName: string;

  @Expose()
  @IsString()
  @IsEmail()
  @ApiProperty({
    description: "user email",
    type: "string",
    default: "user@gmail.com",
  })
  email: string;

  @Expose()
  @IsString()
  @MinLength(6)
  @MaxLength(255)
  @ApiProperty({
    description: "user password",
    type: "string",
    default: "123456",
  })
  password: string;
}

export class LoginDto {
  @Expose()
  @IsString()
  @IsEmail()
  @ApiProperty({
    description: "user email",
    type: "string",
    default: "user@gmail.com",
  })
  readonly email: string;

  @Expose()
  @IsString()
  @MinLength(6)
  @MaxLength(255)
  @ApiProperty({
    description: "user password",
    type: "string",
    default: "123456",
  })
  readonly password: string;
}
