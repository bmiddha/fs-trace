const os = require("os");
const { execSync } = require("child_process");

let addon;

if (os.platform() === "linux" && os.arch() === "x64") {
  try {
    const output = execSync("ldd --version").toString();
    if (/GLIBC\s(\d+\.\d+)/.test(output)) {
      addon = require("@fstrace/linux-x64-glibc");
    } else {
      throw new Error("Unsupported platform or architecture");
    }
  } catch (error) {
    throw new Error("Unsupported platform or architecture");
  }
} else {
  throw new Error("Unsupported platform or architecture");
}

/**
 * @param {string[]} argv
 * @param {(message: string) => void} callback
 * @returns {void}
 */
function exec(argv, callback) {
  if (!Array.isArray(argv)) {
    throw new Error("argv must be an array");
  }
  if (argv.some((arg) => typeof arg !== "string")) {
    throw new Error("argv must be an array of strings");
  }
  addon.exec(argv, callback);
}

module.exports.exec = exec;
