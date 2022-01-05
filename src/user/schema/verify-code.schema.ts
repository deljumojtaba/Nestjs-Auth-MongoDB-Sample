import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import * as mongoose from 'mongoose';

@Schema({timestamps: true})
export class VerifyCode{
    @Prop({type: mongoose.Types.ObjectId, ref: 'User'})
    user: mongoose.Types.ObjectId;
    
    @Prop({type: String, trim: true})
    code: string;
    
    @Prop({type: Date, default: new Date(), expires: '5m'})
    createdAt: Date;
}

export const VerifyCodeSchema = SchemaFactory.createForClass(VerifyCode);