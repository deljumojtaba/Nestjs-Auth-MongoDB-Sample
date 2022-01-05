import { ApiProperty } from "@nestjs/swagger";
import { Expose } from "class-transformer";
import { IsString, MinLength, MaxLength, IsEmail } from "class-validator";

export class SuperAdminDto {
  @Expose()
  @IsString()
  @ApiProperty({
    required: false,
    default: "Mojtaba Delju",
  })
  fullName: string;

  @Expose()
  @IsString()
  @IsEmail()
  @ApiProperty({
    description: "super admin email",
    type: "string",
    default: "admin@gmail.com",
  })
  readonly email: string;

  @Expose()
  @IsString()
  @MinLength(6)
  @MaxLength(255)
  @ApiProperty({
    description: "super admin email",
    type: "string",
    default: "123456",
  })
  readonly password: string;
}
