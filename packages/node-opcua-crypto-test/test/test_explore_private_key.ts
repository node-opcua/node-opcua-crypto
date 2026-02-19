// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------

import path from "node:path";
import { explorePrivateKey, readPrivateKey, readPrivateRsaKey } from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

describe(" exploring Private Key", () => {
  it("should explore a RSA private key", () => {
    const privateKeyRSA = readPrivateRsaKey(path.join(__dirname, "../test-fixtures/certs/alice_id_rsa"));
    const a = explorePrivateKey(privateKeyRSA);
    expect(a.modulus.length).toEqual(2048 / 8);
    expect(a.modulus.toString("hex").toUpperCase()).toEqual(
      "DF59774B8EE24CE9B531A7AE26AF9694F6E4F2D61B9ED84EC39109EF7FF92E709936BD23A496860D274702074E22DEA3330940CE19F60F0046286B48D0D3607831FA58F11721BCDC14481B81D37763C6E761503128EAD316D3A99297E60CE0D5C9B09EA6DE8D89044A6A8ADF71E84D6AEAE7E7639F5245DA436C8780368C4914C312D75450E32B0E5028DC200C509ED76721F721FF313D2F2A94422F85E4D58A1F8E018B0FD22FD970E2F4187D5DBC2A8E8B4C496A168BA53232AA4C15CAAD43F22BE039038934AABA5F47D23C8ACDF9F9CCF65187CCC99B1436EA8A4E3221D3EC70F8E470A925E5D9AACDB480B640FB1EA64F77A74CF267FB4B42C9257DD5D5",
    );
  });

  it("should explore a private key", () => {
    const privateKey = readPrivateKey(path.join(__dirname, "../test-fixtures/certs/demo_key_4096.pem"));
    const a = explorePrivateKey(privateKey);
    expect(a.modulus.length).toEqual(4096 / 8);
    expect(a.modulus.toString("hex").toUpperCase()).toEqual(
      "B31F816D72E524391E436062D41A10351C2E01292E0F010A8BECA3B23535C17096855B921A4D04E0B631DD226AF86E6A75780CF54BFF363ABBDF4505F0E59B741CA99872E0E056F34504E571FD9A4EC6F2A376BF605025136C55D0B006745102943F4F344B7138D64C5A5F76369430903A9F4BB1DB8AC90D52ED8B54EE52F0A2310EDFDA0969A70A1E74FB99D7E49FBC83D3093DE3CCC30EB42C4BA339A02C70C780A7BC9108B5369EE2F6222F43A4C36DC60DF357578C9A4D8D6F8999FB80506C0D73DAFF29CF22ECA4A9CD22296AE66C4D172591348C25440B22C2A547803EF0D83FDE2837639F0DBB22A579FEF012AEB0B303CB8DED0A5B31811949F1144D7BE8F2E73A634BFFE4D8E65CBD6825105DFBE84BFFE30E58BB5AAD78730A6A64E43D961CC3D8DCC439849357982FDE98DB7099651A8B03ECF46839E9DA2818ED4C5883C1E5BDEAD8F29BF18505CCAD17F04EC0E49509A9BE43B5E503EC330E22E4BF28E571DDF81A7E6125D5CD94094BF23753066176D8BE66E5520F64432D5757162CA71AE8870F6D424358676F1C9287623D787EBAF6D0189D085431C7CAB1E7BF37DF282058453083E8BF6D37108EFF455B2C4945AA60D768FCF837B3A7F88AB56731BC569AE73C45220627BF9912BF1E1284B1170CBA0D929A23519D8FC469BF376C61CE62361B9937660DFE70983883E3B6778A5094EB81E202D1DC8B3B",
    );
  });
});
