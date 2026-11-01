import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { loadConfig } from "./config/configuration";
import { applicationOptions, configureApp } from "./http/configure-app";

async function bootstrap(): Promise<void> {
  const config = loadConfig(process.env);
  const app = await NestFactory.create(AppModule, applicationOptions);
  configureApp(app);
  await app.listen(config.port, config.host);
  process.stdout.write(
    `${JSON.stringify({
      level: "info",
      msg: "listening",
      service: "control-plane",
      host: config.host,
      port: config.port,
    })}\n`,
  );
}

void bootstrap().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "startup failed";
  process.stderr.write(`${JSON.stringify({ level: "error", msg: "startup failed", error: message })}\n`);
  process.exit(1);
});
