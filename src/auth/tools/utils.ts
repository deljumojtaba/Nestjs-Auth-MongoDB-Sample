import * as mongoose from "mongoose";
import * as path from "path";
import fs from "fs";
import * as bcrypt from "bcrypt";
import { AuthRequest } from "./../interfaces/auth-request.interface";
import { Response, NextFunction } from "express";
import { Messages } from "./../tools/messages";

const uploadFolder = path.join(
  path.dirname(require.main.filename),
  "/../uploads/"
);

export const isValid = (id: string) => {
  return mongoose.Types.ObjectId.isValid(id);
};

export const deleteFile = (file: string) => {
  if (file !== "default.jpg") {
    const fileDir = uploadFolder + file;
    fs.unlink(fileDir, (err: Error) => {
      if (err) {
        console.log("Error while deleting file");
      }
      return true;
    });
  }
};

export const postUploader = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(409).json({
        status: false,
        message: Messages.THERE_WAS_AN_ERROR_ON_UPLOADING,
      });
    }

    return res.status(201).json({
      status: true,
      message: Messages.PPD_SUCCESS,
      item: `postMedia/${file.filename}`,
    });
  } catch (err) {
    next(err);
  }
};

export const comparePassword = async (
  password: string,
  hashedPassword: string
) => {
  return await bcrypt.compare(password, hashedPassword);
};

export const toObjectId = (id: string) => new mongoose.Types.ObjectId(id);
export const isIdValid = (id: mongoose.Types.ObjectId) =>
  mongoose.Types.ObjectId.isValid(id);
