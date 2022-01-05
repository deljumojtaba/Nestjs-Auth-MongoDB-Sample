import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { Messages } from "./messages";

export class BaseApiResponse<T> {
  constructor(data: T, msg: Messages, succuss: boolean, meta: any) {
    this.data = data;
    this.msg = msg;
    this.success = succuss;
    this.meta = meta;
  }
  public data: T;
  @ApiProperty({ type: String })
  public msg: string;
  @ApiProperty({ type: Boolean })
  public success: boolean;
  @ApiProperty({ type: Object })
  public meta: any;
}

export function SwaggerBaseApiResponse<T>(type: T): typeof BaseApiResponse {
  class ExtendedBaseApiResponse<T> extends BaseApiResponse<T> {
    @ApiProperty({ type })
    public data: T;
  }
  // NOTE : Overwrite the returned class name, otherwise whichever type calls this function in the last,
  // will overwrite all previous definitions. i.e., Swagger will have all response types as the same one.
  const isAnArray = Array.isArray(type) ? " [ ] " : "";
  Object.defineProperty(ExtendedBaseApiResponse, "name", {
    value: `SwaggerBaseApiResponseFor ${type} ${isAnArray}`,
  });

  return ExtendedBaseApiResponse;
}

export class BaseApiErrorObject {
  @ApiProperty({ type: Number })
  public statusCode: number;

  @ApiProperty({ type: String })
  public message: string;

  @ApiPropertyOptional({ type: String })
  public localizedMessage: string;

  @ApiProperty({ type: String })
  public errorName: string;

  @ApiProperty({ type: Object })
  public details: unknown;

  @ApiProperty({ type: String })
  public path: string;

  @ApiProperty({ type: String })
  public requestId: string;

  @ApiProperty({ type: String })
  public timestamp: string;
}

export class BaseApiErrorResponse {
  @ApiProperty({ type: BaseApiErrorObject })
  public error: BaseApiErrorObject;
}
