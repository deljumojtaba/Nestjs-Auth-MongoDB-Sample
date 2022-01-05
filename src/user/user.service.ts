import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { UserDto } from "src/auth/dto/user.dto";
import { Messages } from "src/tools/messages";
import * as _ from "lodash";
import { ProfileDto } from "./dto/profile.dto";
import { User } from "./schema/user.schema";
import { Request } from "express";
import * as bcrypt from "bcrypt";

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  /* ::::::::::::::::::::::::::: get profile :::::::::::::::::::::::::::::: */

  async getProfile(req: Request): Promise<object> {
    try {
      const id = req.user["_id"];

      const currentUser = await this.userModel
        .findById(id)
        .lean()
        .select("-password -__v -updatedAt");

      return currentUser;
    } catch (err) {
      throw new InternalServerErrorException(err.message);
    }
  }

  /* :::::::::::::::::::::::::::::::: end :::::::::::::::::::::::::::::::::: */
}
