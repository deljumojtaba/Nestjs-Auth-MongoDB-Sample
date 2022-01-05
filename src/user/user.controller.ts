import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  Post,
  Put,
  Query,
  Req,
  UnauthorizedException,
  UploadedFile,
  UseGuards,
  UseInterceptors,
  UsePipes,
  ValidationPipe,
} from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import {
  ApiBearerAuth,
  ApiConsumes,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import { Roles } from "src/auth/tools/roles.decorator";
import { RolesGuard } from "src/auth/tools/roles.guard";
import {
  BaseApiResponse,
  SwaggerBaseApiResponse,
} from "src/tools/baseApiResponse.dto";
import { Messages } from "src/tools/messages";
import { ProfileDto } from "./dto/profile.dto";
import { UserService } from "./user.service";
import { Request } from "express";


@Controller("user")
export class UserController {
  constructor(private userService: UserService) {}

  

  /* ::::::::::::::::::::::::::::::::: get profile ::::::::::::::::::::::::::::::: */

  @ApiTags("user")
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    type: UnauthorizedException,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    type: SwaggerBaseApiResponse({}),
  })
  @ApiOperation({
    summary: "get profile user",
  })
  @HttpCode(HttpStatus.OK)
  @UsePipes(ValidationPipe)
  @Roles("user")
  @UseGuards(AuthGuard("jwt"), RolesGuard)
  @ApiBearerAuth()
  @Get("/profile")
  async getProfile(@Req() req: Request): Promise<BaseApiResponse<{}>> {
    const data = await this.userService.getProfile(req);
    if (data) {
      return {
        data,
        success: true,
        msg: Messages.PPD_SUCCESS,
        meta: {},
      };
    }
    throw new NotFoundException({
      data,
      success: false,
      msg: Messages.PPD_FAILURE,
      meta: {},
    });
  }

  /* ::::::::::::::::::::::::::::::::::::: end :::::::::::::::::::::::::::::::::::: */

  
}
