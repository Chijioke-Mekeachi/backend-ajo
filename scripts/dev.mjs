import { spawn } from "node:child_process";
import { existsSync } from "node:fs";

function hasLocalBin(name) {
  const suffix = process.platform === "win32" ? ".cmd" : "";
  return existsSync(new URL(`../node_modules/.bin/${name}${suffix}`, import.meta.url));
}

const command = hasLocalBin("nodemon") ? "nodemon" : "tsx";
const args = command === "nodemon" ? ["--config", "nodemon.json"] : ["watch", "src/server.ts"];

if (command !== "nodemon") {
  console.log('nodemon not found; falling back to "tsx watch".');
  console.log('To use nodemon, run: npm -C backend i -D nodemon');
}

const child = spawn(command, args, { stdio: "inherit", shell: true });
child.on("exit", (code) => process.exit(code ?? 1));
