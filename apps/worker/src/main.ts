import { runWorker } from "./runtime";

const exitCode = await runWorker();
if (exitCode !== 0) {
  process.exitCode = exitCode;
}