const fs = require("fs");

const dir = `/tmp/foo-${new Date().getTime()}`;
console.log(dir);

console.log("mkdirSync");
fs.mkdirSync(dir);

console.log("writeFileSync");
fs.writeFileSync(`${dir}/bar`, "hello");

console.log("readdirSync");
fs.readdirSync(dir);

console.log("readFileSync");
fs.readFileSync(`${dir}/bar`);

console.log("unlinkSync");
fs.unlinkSync(`${dir}/bar`);

console.log("rmdirSync");
fs.rmdirSync(dir);
