import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const directory = resolve(import.meta.dirname);
const inputs = {
  PANEL_PY_B64: "panel.py",
  DOCKERFILE_B64: "Dockerfile",
  SSHD_CONFIG_B64: "sshd_config",
  COMPOSE_B64: "docker-compose.yml",
};

let installer = readFileSync(resolve(directory, "install.template.sh"), "utf8");
for (const [placeholder, filename] of Object.entries(inputs)) {
  const encoded = readFileSync(resolve(directory, filename)).toString("base64");
  installer = installer.replace(`__${placeholder}__`, encoded);
}
if (/__[A-Z0-9_]+__/.test(installer)) {
  throw new Error("Installer still contains unresolved placeholders");
}
writeFileSync(resolve(directory, "install.sh"), installer, { mode: 0o755 });
