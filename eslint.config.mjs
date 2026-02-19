import path from "node:path";
import { fileURLToPath } from "node:url";
import { FlatCompat } from "@eslint/eslintrc";
import js from "@eslint/js";
import typescriptEslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all,
});

export default [
    {
        ignores: ["**/dist-esm", "**/dist*", "**/doc", "**/*.min.js", "**/node_modules", "**/dist", "**/*.js", "**/*.mjs"],
    },
    ...compat.extends("eslint:recommended", "plugin:@typescript-eslint/recommended", "prettier"),
    {
        plugins: {
            "@typescript-eslint": typescriptEslint,
        },

        languageOptions: {
            parser: tsParser,
            ecmaVersion: 2018,
            sourceType: "module",
        },

        rules: {
            "@typescript-eslint/camelcase": "off",
            "@typescript-eslint/no-unused-vars": "off",
            "@typescript-eslint/no-non-null-assertion": "off",
            "@typescript-eslint/no-empty-interface": "off",
            "@typescript-eslint/no-var-requires": "off",
            "@typescript-eslint/no-explicit-any": "off",
            "no-constant-condition": "off",
        },
    },
];
