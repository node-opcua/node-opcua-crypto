import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: ["test/test_*.ts"],
        testTimeout: 200_000,
    },
});
