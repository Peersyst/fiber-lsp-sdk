import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import tseslint from "typescript-eslint";

export default tseslint.config(
    { ignores: ["dist", "coverage", "node_modules"] },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    prettier,
    {
        files: ["src/**/*.ts"],
        ignores: ["src/**/*.spec.ts"],
        rules: {
            "no-restricted-imports": [
                "error",
                {
                    patterns: [
                        {
                            group: ["node:*"],
                            message:
                                "The SDK must run in Node, browsers and React Native (Hermes): no platform APIs, inject every external effect.",
                        },
                    ],
                    paths: [
                        "fs",
                        "path",
                        "os",
                        "crypto",
                        "http",
                        "https",
                        "net",
                        "tls",
                        "zlib",
                        "stream",
                        "buffer",
                        "events",
                        "util",
                        "url",
                        "child_process",
                        "worker_threads",
                    ],
                },
            ],
        },
    },
);
