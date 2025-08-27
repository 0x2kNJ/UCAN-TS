import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.spec.ts"],
    setupFiles: [],
    reporters: ["default"],
    testTimeout: 30000,
    coverage: {
      reporter: ["text", "html"],
    },
  },
});
