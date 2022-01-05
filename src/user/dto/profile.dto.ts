import { ApiProperty } from "@nestjs/swagger";
import { Expose } from "class-transformer";
import { IsBoolean, IsOptional, IsString } from "class-validator";
import * as mongoose from "mongoose";

export class ProfileDto {
  @Expose()
  @IsString()
  @ApiProperty({
    required: false,
    default: "",
  })
  fullName: string;

  @Expose()
  @IsString()
  @ApiProperty({
    required: false,
    default: "",
  })
  email: string;

  @Expose()
  @IsString()
  @ApiProperty({
    required: false,
    default: "",
  })
  newPassword: string;

  @Expose()
  @IsString()
  @ApiProperty({
    required: false,
    default: "",
  })
  oldPassword: string;

  @Expose()
  @IsBoolean()
  @ApiProperty({
    required: true,
    default: true,
  })
  gender: boolean;

  @Expose()
  @IsString()
  @ApiProperty({
    required: false,
    default: "30/3/2000",
  })
  birthday: string;
}
