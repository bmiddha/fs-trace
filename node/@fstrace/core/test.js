const { exec } = require(".");
const path = require("path");

exec(["node", path.resolve("fstest.js")], console.log);
