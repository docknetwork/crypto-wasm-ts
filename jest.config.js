const pack = require("./package");

module.exports = {
  preset: "ts-jest",
  roots: ["<rootDir>/tests"],
  testEnvironment: "node",
  testPathIgnorePatterns: ["/node_modules/", "/output/"],
  testRegex: [".spec.ts$"],
  moduleFileExtensions: ["ts", "js", "json", "node"],
  coveragePathIgnorePatterns: ["<rootDir>/__tests__", "<rootDir>/lib"],
  testTimeout: 20000,
  verbose: true,
  name: pack.name,
  displayName: pack.name,
};
