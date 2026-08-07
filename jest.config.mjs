export default {
    testEnvironment: "node",
    rootDir: ".",
    // Scoped to test/tests so the helpers in test/utils are not collected as suites.
    testRegex: "/test/tests/.*\\.spec\\.ts$",
    // The runtime dependencies are ESM only, so jest has to transpile them like sources.
    transform: {
        "^.+\\.[tj]s$": ["ts-jest", { tsconfig: { allowJs: true } }],
    },
    transformIgnorePatterns: ["node_modules/(?!.*(@noble|@scure))"],
    collectCoverageFrom: ["src/**/*.ts"],
};
