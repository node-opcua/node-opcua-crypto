import fs from "node:fs";
import path from "node:path";

function createEsmModulePackageJson(buildDir) {
    if (!fs.existsSync(buildDir)) {
        return;
    }
    var packageJsonFile = path.join(buildDir, "/package.json");
    if (!fs.existsSync(packageJsonFile)) {
        fs.writeFileSync(packageJsonFile, '{"type": "module"}', "utf-8");
    }
}

createEsmModulePackageJson("./dist-esm/source");
createEsmModulePackageJson("./dist-esm/");
