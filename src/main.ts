import { ValidationPipe } from "@nestjs/common";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { ConfigService } from "@nestjs/config";

/*/

                                                                                                              
 ██████   ██████               ███   █████              █████                  ██████████            ████       ███            
░░██████ ██████               ░░░   ░░███              ░░███                  ░░███░░░░███          ░░███      ░░░             
 ░███░█████░███   ██████      █████ ███████    ██████   ░███████   ██████      ░███   ░░███  ██████  ░███      █████ █████ ████
 ░███░░███ ░███  ███░░███    ░░███ ░░░███░    ░░░░░███  ░███░░███ ░░░░░███     ░███    ░███ ███░░███ ░███     ░░███ ░░███ ░███ 
 ░███ ░░░  ░███ ░███ ░███     ░███   ░███      ███████  ░███ ░███  ███████     ░███    ░███░███████  ░███      ░███  ░███ ░███ 
 ░███      ░███ ░███ ░███     ░███   ░███ ███ ███░░███  ░███ ░███ ███░░███     ░███    ███ ░███░░░   ░███      ░███  ░███ ░███ 
 █████     █████░░██████      ░███   ░░█████ ░░████████ ████████ ░░████████    ██████████  ░░██████  █████     ░███  ░░████████
░░░░░     ░░░░░  ░░░░░░       ░███    ░░░░░   ░░░░░░░░ ░░░░░░░░   ░░░░░░░░    ░░░░░░░░░░    ░░░░░░  ░░░░░      ░███   ░░░░░░░░ 
                          ███ ░███                                                                         ███ ░███            
                         ░░██████                                                                         ░░██████             
                          ░░░░░░                                                                           ░░░░░░              
         
/*/
async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true });
  const config = app.get(ConfigService);
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })
  );
  app.setGlobalPrefix("v1");
  const options = new DocumentBuilder()
    .setTitle("auth Api Docs V1 Nest.js")
    .setDescription(`BASE API HOST : ${process.env.IP}/docs`)
    .setVersion("1.0")
    .addTag("user")
    .addTag("api")
    .addTag("superadmin")
    .addBearerAuth({
      type: "http",
      scheme: "Bearer",
      bearerFormat: "JWT",
      in: "header",
    })
    .build();
  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup("api/docs", app, document);

  await app.listen(process.env.PORT || 3003, () => {
    console.log(
      `app running on port ${process.env.PORT} in ${process.env.NODE_ENV}`
    );
  });
}
bootstrap().then(() => {
  console.log(`App successfully started on ${process.env.IP}/docs`);
});
