import { exploreCertificate } from "node-opcua-crypto/web";
import { expect, it } from "vitest";

it("should import exploreCertificate from node-opcua-crypto/web", () => {
    expect(exploreCertificate).toBeDefined();
});
