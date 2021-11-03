import { initializeWasm } from "../../lib";
import { SignatureParamsG1 } from "../../lib/ts";

describe("Full demo", () => {
  it("runs", async () => {
    await initializeWasm();

    console.log(SignatureParamsG1.generate(6));
  })
});
