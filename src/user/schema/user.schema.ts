import * as bcrypt from "bcrypt";
import * as mongoose from "mongoose";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema({ timestamps: true })
export class User extends mongoose.Document {
  @Prop({ type: String, trim: true, default: null })
  fullName: string;

  @Prop({ type: String, required: true, select: false })
  password: string;

  @Prop({ type: String, default: "defaults/userAvatar.png" })
  userAvatar: string;

  @Prop({ type: Boolean, default: false })
  block: boolean;

  @Prop({
    type: String,
    required: true,
    trim: true,
    enum: ["superadmin", "user"],
    default: "user",
  })
  role: string;

  @Prop({
    type: String,
    required: false,
    trim: true,
    enum: ["male", "female", "other", "unknown"],
    default: "unknown",
  })
  gender: string;

  @Prop({ type: String, trim: true, default: null })
  birthday: string;

  @Prop({ type: String, required: true, trim: true, unique: true })
  email: string;

  @Prop({ type: String, trim: true, default: null })
  mobile: string;

  @Prop({ type: Number, default: 0 })
  wallet: number;

  @Prop({ type: Boolean, default: false })
  isEmailVerified: boolean;

  validatePassword = async function (password: string): Promise<boolean> {
    const hash = await bcrypt.hash(password, 10);
    return hash === this.password;
  };
}

export const UserSchema = SchemaFactory.createForClass(User);
