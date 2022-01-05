import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User } from "src/user/schema/user.schema";
import * as Cryptr from "cryptr";
import { JwtPayload } from "./interfaces/jwt-payload.interface";
import * as bcrypt from "bcrypt";
import { Messages } from "src/tools/messages";
import { SuperAdminDto } from "./dto/superadmin.dto";
import { sign } from "jsonwebtoken";
import { LoginDto, UserDto } from "./dto/user.dto";
import { nanoid } from "nanoid";
import { BaseApiResponse } from "src/tools/baseApiResponse.dto";
import { comparePassword } from "./tools/utils";

@Injectable()
export class AuthService {
  cryptr: any;
  constructor(@InjectModel(User.name) private userModel: Model<User>) {
    this.cryptr = new Cryptr(process.env.ENCRYPT_JWT_SECRET);
  }

  /* ::::::::::::::::::::::::::::: register super admin :::::::::::::::::::::::::::::: */

  async registerSuperAdmin(superadminDto: SuperAdminDto): Promise<object> {
    const { email, password, fullName } = superadminDto;

    const isSuperAdminExist = await this.userModel.findOne({
      $or: [{ role: "superadmin" }, { email }],
    });

    if (isSuperAdminExist) {
      throw new ConflictException("super admin already exist");
    }

    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(password, salt);

    const data = {
      fullName,
      password: hash,
      role: "superadmin",
      email,
    };

    const user = await new this.userModel(data).save();
    const userId = user._id;
    const accessToken = await this.createAccessToken(userId);

    const doc = user.toObject();
    const toJson = JSON.stringify(doc);
    const item = JSON.parse(toJson);
    delete item["password"];

    const response = {
      item,
      accessToken,
    };
    return response;
  }

  /* :::::::::::::::::::::::::::::::::::::: end :::::::::::::::::::::::::::::::::::::: */

  /* :::::::::::::::::::::::::::::::::: register user :::::::::::::::::::::::::::::::: */

  async registerUser(userDto: UserDto): Promise<object> {
    const { email, password, fullName } = userDto;

    const isUserExists = await this.userModel.findOne({ email });

    if (isUserExists) {
      throw new ConflictException(Messages.DUPLICATE_DATA);
    }

    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(password, salt);

    const user = await new this.userModel({
      email,
      password: hash,
      fullName,
    }).save();

    if (!user) {
      throw new InternalServerErrorException(Messages.PPD_FAILURE);
    }

    const item = {
      email: user.email,
      role: user.role,
      _id: user._id,
      fullName: user.fullName,
      isEmailVerified: user.isEmailVerified,
    };

    const accessToken = await this.createAccessToken(user._id);
    const response = {
      item,
      accessToken,
    };
    return response;
  }

  /* :::::::::::::::::::::::::::::::::::::: end :::::::::::::::::::::::::::::::::::::: */

  /* ::::::::::::::::::::::::::::::::: login all users ::::::::::::::::::::::::::::::: */

  async loginAllUser(loginDto: LoginDto): Promise<object> {
    const { email, password } = loginDto;

    const user = await this.userModel
      .findOne({ email, block: false })
      .select("+password -updatedAt -__v")
      .lean();

    if (!user) {
      throw new NotFoundException(
        `${Messages.WRONG_CREDENTIALS} or ${Messages.BLOCKED}`
      );
    }

    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      throw new UnauthorizedException(Messages.WRONG_CREDENTIALS);
    }

    const accessToken = await this.createAccessToken(user._id);

    delete user.password;
    const response = {
      item: user,
      accessToken,
    };
    return response;
  }

  /* :::::::::::::::::::::::::::::::::::::: end :::::::::::::::::::::::::::::::::::::: */

  /* ::::::::::::::::::::::::::::::::: validate user ::::::::::::::::::::::::::::::::: */

  async validateUser(jwtPayload: JwtPayload): Promise<any> {
    const user = await this.userModel.findOne({
      _id: jwtPayload.userId,
    });
    if (!user || user.block) {
      throw new UnauthorizedException(Messages.BLOCKED);
    }
    return user;
  }

  /* :::::::::::::::::::::::::::::::::::::: end ::::::::::::::::::::::::::::::::::::::: */

  /* :::::::::::::::::::::::::::::::::: jwt extractor ::::::::::::::::::::::::::::::::: */

  private jwtExtractor(request) {
    let token = null;
    if (request.header("x-token")) {
      token = request.get("x-token");
    } else if (request.headers.authorization) {
      token = request.headers.authorization
        .replace("Bearer ", "")
        .replace(" ", "");
    } else if (request.body.token) {
      token = request.body.token.replace(" ", "");
    }
    if (request.query.token) {
      token = request.body.token.replace(" ", "");
    }
    const cryptr = new Cryptr(process.env.ENCRYPT_JWT_SECRET);
    if (token) {
      try {
        token = cryptr.decrypt(token);
      } catch (err) {
        throw new BadRequestException("the token is invalid!");
      }
    }
    return token;
  }

  returnJwtExtractor() {
    return this.jwtExtractor;
  }

  /* :::::::::::::::::::::::::::::::::::::: end ::::::::::::::::::::::::::::::::::::::: */

  /* ::::::::::::::::::::::::::::::: create access token :::::::::::::::::::::::::::::: */

  async createAccessToken(userId: string) {
    const accessToken = sign({ userId }, process.env.TOKEN_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });
    return this.encryptText(accessToken);
  }

  encryptText(text: string): string {
    return this.cryptr.encrypt(text);
  }

  /* :::::::::::::::::::::::::::::::::::::: end ::::::::::::::::::::::::::::::::::::::: */
}
