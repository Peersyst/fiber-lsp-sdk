import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import jsdoc from "eslint-plugin-jsdoc";
import tseslint from "typescript-eslint";

const RUNTIME_MESSAGE = "The SDK must run in Node, browsers and React Native (Hermes): no platform APIs, inject every external effect.";

const PLATFORM_GLOBALS = [
    "process",
    "Buffer",
    "global",
    "__dirname",
    "__filename",
    "require",
    "module",
    "exports",
    "window",
    "document",
    "navigator",
    "localStorage",
    "sessionStorage",
    "XMLHttpRequest",
    "WebSocket",
    "fetch",
    "crypto",
];

const RELATIVE_IMPORT_PATTERNS = [
    {
        group: ["./*.js", "./**/*.js", "../*.js", "../**/*.js"],
        message: "Relative imports carry no file extension: the package is CommonJS, so NodeNext resolves them without one",
    },
    {
        group: ["./index", "./**/index", "../index", "../**/index"],
        message: "A barrel is imported as its folder, never as its index file",
    },
];

const NODE_BUILTINS = [
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
];

// Exported functions only. Internal helpers are read next to their single caller and
// do not earn a comment.
const DOCUMENTED_EXPORTS = [
    "ExportNamedDeclaration > FunctionDeclaration",
    "ExportNamedDeclaration > VariableDeclaration > VariableDeclarator > ArrowFunctionExpression",
    "ExportDefaultDeclaration > FunctionDeclaration",
    "ExportDefaultDeclaration > ArrowFunctionExpression",
];

// One-line summary, capitalised, ending in a full stop, no extra paragraphs: anything
// more belongs in docs/.
const ONE_LINE_SUMMARY = "^[A-Z`\\{][^\\n]*\\.$";

export default tseslint.config(
    { ignores: ["dist", "coverage", "node_modules"] },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    jsdoc.configs["flat/recommended-typescript-error"],
    prettier,
    {
        rules: {
            // Re-enabled for src below. Test helpers and internal functions carry no JSDoc.
            "jsdoc/require-jsdoc": "off",
            "jsdoc/require-description": "error",
            "jsdoc/require-param": ["error", { checkDestructured: false }],
            "jsdoc/check-param-names": ["error", { checkDestructured: false }],
            "jsdoc/require-hyphen-before-param-description": ["error", "never"],
            // `/** text */` on one line is never allowed, not even for a single sentence.
            "jsdoc/multiline-blocks": ["error", { noSingleLineBlocks: true, noMultilineBlocks: false }],
            "jsdoc/match-description": [
                "error",
                {
                    message: "The description must fit on one line, start with a capital and end with a full stop.",
                    matchDescription: ONE_LINE_SUMMARY,
                    tags: { param: true, returns: true },
                },
            ],
        },
    },
    {
        files: ["src/**/*.ts"],
        rules: {
            "jsdoc/require-jsdoc": ["error", { require: { FunctionDeclaration: false }, contexts: DOCUMENTED_EXPORTS }],
        },
    },
    {
        // src only: test/ runs under Node and may use platform APIs freely.
        files: ["src/**/*.ts"],
        rules: {
            "no-restricted-imports": [
                "error",
                {
                    patterns: [{ group: ["node:*"], message: RUNTIME_MESSAGE }, ...RELATIVE_IMPORT_PATTERNS],
                    paths: NODE_BUILTINS,
                },
            ],
            "no-restricted-globals": ["error", ...PLATFORM_GLOBALS.map((name) => ({ name, message: RUNTIME_MESSAGE }))],
        },
    },
    {
        files: ["test/**/*.ts"],
        rules: {
            "no-restricted-imports": ["error", { patterns: RELATIVE_IMPORT_PATTERNS }],
        },
    },
);
