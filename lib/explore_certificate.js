var assert = require("better-assert");

var readPEM = require("./crypto_utils").readPEM;
/**
 * @method exploreCertificate
 * @param certificate
 * @return object.publicKeyLength
 * @return object.notBefore
 * @return object.notAfter
 */
var a = 1;
exports.exploreCertificate = function (certificate) {

    var exploreCertificate = require("./crypto_explore_certificate").exploreCertificate;

    if (typeof certificate === "string") {
        certificate = readPEM(certificate);
    }
    assert(certificate instanceof Buffer);

    var certInfo = exploreCertificate(certificate);

    var data = {
        publicKeyLength: certInfo.tbsCertificate.subjectPublicKeyInfo.keyLength,
        notBefore:       certInfo.tbsCertificate.validity.notBefore,
        notAfter:        certInfo.tbsCertificate.validity.notAfter
    };
    assert(data.publicKeyLength === 256 || data.publicKeyLength === 128);
    return data;
};
