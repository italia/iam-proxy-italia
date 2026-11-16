import js from "@eslint/js";
import globals from "globals";

export default [
  { ignores: ["**/bootstrap-italia/**", "**/*.min.js", "**/jquery*.js", "**/brython.js", "**/bootstrap-italia*.js"] },
  js.configs.recommended,
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        ...globals.browser,
        i18next: "readonly",
        i18nextHttpBackend: "readonly",
        Ita: "readonly",
      },
    },
    rules: {
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
      "no-console": ["warn", { allow: ["warn", "error"] }],
    },
  },
];
