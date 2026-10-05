import { base } from "@v-m-pioneer-trading/eslint-config";

// contract/ is its own project (its own tsconfig, package.json and lockfile) and is never edited by a port. It was never
// linted, and the repository root now contains it.
export default base({ tsconfigRootDir: import.meta.dirname, ignores: ["contract/**"] });
