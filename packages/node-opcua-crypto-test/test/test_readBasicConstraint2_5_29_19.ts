import assert from "node:assert";
import { asn1, coerceCertificate, readTbsCertificate } from "node-opcua-crypto";

/*
  The folowing test certificates should reflect the following configurations of
  openssl x509_v3 extensions:
  1. basicConstraints = critical, CA:false
  2. basicConstraints = critical, pathlen:0
  3. basicConstraints = critical, CA:false, pathlen:0
  4. basicConstraints = critical, CA:true, pathlen:0
*/
const CERT_1 = `-----BEGIN CERTIFICATE-----
MIIFKjCCAxKgAwIBAgIUXaOivneL1a7HH5IOb5QvNKbkk9wwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwacmVhZEJhc2ljQ29uc3RyYWludC4xLnRlc3QwIBcNMjMw
OTAxMTUxMjA3WhgPMjEyMzA4MDgxNTEyMDdaMCUxIzAhBgNVBAMMGnJlYWRCYXNp
Y0NvbnN0cmFpbnQuMS50ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAwGdNeiOVzKhL3xMk28vzfFD12iH+cfL3NVXaedSfLS+bhUCKawZAd7TkLdl6
jgNDTqJ4zshWr2Weaxl4gSeKm8fAJdUvDWTj3qCW1hQQmbvbdap9v5ReLEtrmuIT
ptgZzx4UJxOoOUm1NZFkge0+D2BBpwt9LbZ4c66L1y7sorXlq+vIgx20dIfzjEnL
cjXYjjnfiF5jsYQc8zQDroUtltWhujq3d+Z6AITE56k7Mx2NDex3RU6ojVf8pkOZ
8nFChtFzavH3hCkLdznXILlUuiZ0p+P5FO/oqJK/e7BH5vKHqKQabAlecyOTUe9P
MusH7lnT6u6bSfsnPIr2S4OcOAU0UQe4NJotKYKerf3tzGkTuOqVTlW0Ep0fcwig
A5phlW0lJYIN7ny6C7ev4tRc6skqI0KpECPfFuZ2DIdUaeVTwjpfOBEtHS9LbiHq
CwcEakVInO2N7Wd1ZamNqH9TqXqLd5UkM1IF7NSKj5ahmY64jaxP1nRVtCl2xVF9
zvJ5e/KmDBIzy5uyWif7s7rwKCoTJUKtgUV8kM7oQoU8FxdvHegZ4J10NIWY3BuL
43aPGImU4q0uDudLmBufEpi9gMJnf+3ObO18+A3uT0s9ZdJbl6NetMYHtio8uk0/
dxaGCbju6QJ9Rq3ywPIt4DxHUhTUXlvIO+yKB1Ot0HF8CXMCAwEAAaNQME4wHQYD
VR0OBBYEFLjCDY3voIiD5c3XhaWbGxDNfJj0MB8GA1UdIwQYMBaAFLjCDY3voIiD
5c3XhaWbGxDNfJj0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBABAH
FYyLw814T4DSnveeUM6O0zqIMuNIROFQPiTRbvMyYMnhhe2E2K/2P9DOzS1OzWK3
/KgSRujTGEB/R18ba/eyASfp5FLku1XgaorGab+GU/7ot4wfclDa4DtpkGqh1GXa
Z/jUJUAVPf9NNoB1dxkZq6lFIUCsjBIXF1uNjqN4lHG9y8IOWo4lwg78gwabys8T
Q4GFGy1ZyN6PcEUuqMt0C7297Qc/B5+UcivZGRTTLGsxmZhue7RX7fa8osOdFohc
mpcbyxksvKz195wG2IkIdDb6sYO+4xNSVQcFaMDrduAOKKdEPN+bHra+YN5vU2IV
gYA4w/es27juvK0JmwHbbi9hVrhAJzjoZ31jtDxWsOcHfkbyr1kHi2cvfhvu4MKI
I2BAmDCgpYSCixmi44r+o/B/m2UwyO5TRosPN/Qsx143QaN1K7edDR1imegmhlay
9s7rdxqJCH8OnTdpe2BCt0s3T5dfyvjNmHW6s4xOYiy5LmWzhNVQUGyfVMJjMfOa
J4sY0HlkxQWpvfN19tse/UNq2ORhYDxva7yblUljcAsDlaF5eZe+8eKkCNsg4ugk
OcF1u7VvAyq4n3V97cm0za7GsIdC/IKgb9w2aFW8k/g26RUCFyp813IEv63VSaSB
JusO1Rnxw+1CFrEV2K4bAXU9roS0sz2zvx3dh32h
-----END CERTIFICATE-----`;

const CERT_2 = `-----BEGIN CERTIFICATE-----
MIIFLTCCAxWgAwIBAgIUCN0fSyBLHVoXRHgGkYBzXK9EvD8wDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwacmVhZEJhc2ljQ29uc3RyYWludC4yLnRlc3QwIBcNMjMw
OTAxMTUxMjA3WhgPMjEyMzA4MDgxNTEyMDdaMCUxIzAhBgNVBAMMGnJlYWRCYXNp
Y0NvbnN0cmFpbnQuMi50ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAxS6nIT5neOGn4VHfUUBIIj8FkfBfweKeNr2pRR2DLMZGUgAiJ2+LXuRvIFOq
mMX5rczK2dMlbb5r3f9bg9ZHJIf7Yf9nifzl6hxq7nwNqf3woJcpht5ZhmRiF96s
ZOGgKShtej8SVljZ16qAKii9lXgIDy/d5tfvMUdn57BPqiKttyHQdy4ED4aYABSL
zJbId8E3FE3qSExyjNZRDEruLc0Ik/BaLT2zcKatxvruvKHWFefgFLiv/do6++27
WctJOPRL4RhrPgy1Th/SAH8pXcebfQwmgUiuDK9n0u48eezyR753qcSVtkGFYNUn
2Tk7TfUTjYqGqF4mmaCZ8fn9UjkMjYDyJHHxTzbQLLD6eD629T7J52NXs5vpATJJ
B5u0bszTj2D904yqPfhPKYPK+FMPVWbnAPvth8wfjRSi2qltAezXEWBfg3MkoFgd
dlpWtQeplVQdwuC3P84Y0MNTOZ+Y/wcXKUIE9UshRCgPZtUFRb6NxJPKiSe4sK0J
c7iddxfg9Vv0Fc8Rt9GvX3M0akan/8Ogs0T9UOqGCQmT4oJVICB/LQZZAU6wmGMr
TulneUfqqubbU/03A64hT/HVin4mdbsEFQKGGPrTqFeZ82N5fNuZ8zsXy9WbVmY4
3HUgS858Bx7EZVcyQu77Wwdt7jwVT1ZxkcVAamaQnCsGjQ0CAwEAAaNTMFEwHQYD
VR0OBBYEFG1Ud691GfBqz3aSboUmwrYRWrmwMB8GA1UdIwQYMBaAFG1Ud691GfBq
z3aSboUmwrYRWrmwMA8GA1UdEwEB/wQFMAMCAQAwDQYJKoZIhvcNAQELBQADggIB
AIqPBKr1V4xrJBOtryDV1xDOCecFoMQXjTkeaPDKgUOCyy0QK8yQlTsa3CdXfhMF
Q6wJ1OCEwo2LnghEs88KgkhV+hIWH69S/88eVDc7ztTxG6GNHThqq3sronwLo+y3
1VEbvTONFpHhqBesDXuwQ1hbTL1WKl2iwKiUmG/MqrQ+zn7Maa1EQivwy2xF68/s
KMlbA1/K6ftQOIinpkUfWfleizPrg2uk5fpyvF7OasGp/Bqg2i9lG7vRGlha8EqS
dhuIAMCAEnWygsMue43r0wSr2dfijz9RhMvBdnvR5FNXzUQKkFSfHK9zjiKQRaCb
uYPofZj4f7z61F98q6AcX1vpCyboo+ikcPY4nR7dad35VKcBEfiwbKyC57R63Rcv
zQOvpj71oapEtVxKku7sksGuynsFL77uvLXu4dDyP/Qh1dk2qiJYujmCHxCJeBqG
A6HUOJ1mSDK2W9MY7LhFGXFjW17gUsOhXccPq61LMcdPsnxX3ZGqjSQS3S6ZTW21
ejLuZTBui/Bj1P9wHWXH63WLBf6eWx0MA1keKxguUjqIRkFnsaGQvJ37gZOOACOu
5ALPa3eTv5/P2A7s9s1mzLyjQfUNNrK4N5iRE3TUBr8QfNq1ULD3qo6EXmWz0CSJ
RM//xentknWuHSqin8bo/gAZqNWz1/gnbppo3oBADthn
-----END CERTIFICATE-----`;

const CERT_3 = `-----BEGIN CERTIFICATE-----
MIIFLTCCAxWgAwIBAgIUO5QVmZxK1bq9+kNe06kM8eY2QEIwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwacmVhZEJhc2ljQ29uc3RyYWludC4zLnRlc3QwIBcNMjMw
OTAxMTUxMjA3WhgPMjEyMzA4MDgxNTEyMDdaMCUxIzAhBgNVBAMMGnJlYWRCYXNp
Y0NvbnN0cmFpbnQuMy50ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEA1RRUaB2DpGoGdi23le2OlRt84/0zL25kSqnuqNihsucgdEoAvCzOZhRlhoVH
8JCxTU+WQsis6cp5PPWBKsbv58KfHlYpLPcPCgGqMx+G0Ru8i5383z8sHqtKU7x3
G0CPVfu1iqjAhPixTLvU4K9lRB7VkDT/yAtAYmlZ42D6lwvi4Z+3DPy9lmYV5fpt
WgLHoDAuP7X1BvAqlJF+4KvakwISVn+eegB3x6oN/KPF4jb5diWLEspPNmblezFt
67I7skoCYt2Xf15bXwSO6YiCSL0Jj6ecPmVtD4eqmkCfqmAPFHsmm5g86ZTIIAgV
JNwB2kub/EjHQfcJlR92FZbj8pmUDppskJ0KHPE2tgrJOya6cFpTOj45TF03XqWT
xhpcwkkw+bzb6oke5mVK8Okh85C9SaNkQzm3PLlp+GFQZQbs2xeNBV1VGrJ03rUM
whQFZ/yzH2mRIjz3Wz/cLdXBzbPLsFFhqamtCOjKx99WS5Z0iYJFP2RW/+e0iPsb
z3vsBB+rGbtzILMaqIGp0G7ajhBxR8kKtBMvGtcfA2Ys9/apalKhDuqmhMB6aUB9
woJgh/u5GtDBvmwecVZkR60FK1wvY65vyVNzdKqypoCgIiVbYqBcjhZjQo1/r4Ff
PdBUJ1IahlOhRa3/BvRSOr3DOKLZ5GqB+Q1kD24HbZdPbZkCAwEAAaNTMFEwHQYD
VR0OBBYEFEgvK+9o3mN1pdXItLezN2nig2iQMB8GA1UdIwQYMBaAFEgvK+9o3mN1
pdXItLezN2nig2iQMA8GA1UdEwEB/wQFMAMCAQAwDQYJKoZIhvcNAQELBQADggIB
AKaHhpFPFFnphc1n8aiNEkUjFZwgH+BBc7JsbOE+au3mrZjQiwkEN6Ry9NZFOzwe
YnSvnHl0Nf0KsJ6wNfbun1m6jSamhQR24R1fKzM9aw6NLFTYFHUhwEgqV+/7SuRs
JYH8l46HK3/ioBXUb0UBw5R5XZA9lgCrJT1ASJ78IQKjxWNFO1dTYCcSYJX6W/Aw
U6RMRAckFaHcM3B+zVuli5nj9bgLM3YkmKYd2QpsGk57O49+pH4HmS3jLoT9EjaH
TH3N+sOeiCf5caVumXkAjuuvljQ5EqFAOtMdSECM4P9sPMqJLkaZQQt4maB2GOKS
deqCgTOINFdV9ToILmrnVXXK0aYqZJhJReHXgH6Eo7e08yIC4Kc8JsmdilLtgkJr
wlHTQAk15b0p4Xn4jz0NUz/AEehv0RGS7MWbamJWw0wPze9UwJSVCQvI5uYAye8d
dPX/A4aC75Kk/g4lp3ji+Etu3WbPQM9GIY8py2DbHAxmY+GIS4EUf75/bo1PiaNC
Iz6wpQRePFMC+WVk+Yl4DyoEKzDXR0w8DdqARGZ7ysVZj4B7yfo6SWYlSuAitoY/
+NbYp4YuViFWqT2j23MLXn3/5xQ43ZUYF66Q5PT8zdvORzrSvUXMNZUOdKONgSMK
FmWV1CGvFIIi+vRYUlp6qVIw7b7PL4FtQLxb2rjtIFP7
-----END CERTIFICATE-----`;

const CERT_4 = `-----BEGIN CERTIFICATE-----
MIIFMDCCAxigAwIBAgIUZ70n7eBbkSi2T7MU6vSg9yYbrFUwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwacmVhZEJhc2ljQ29uc3RyYWludC40LnRlc3QwIBcNMjMw
OTAxMTUxMjA3WhgPMjEyMzA4MDgxNTEyMDdaMCUxIzAhBgNVBAMMGnJlYWRCYXNp
Y0NvbnN0cmFpbnQuNC50ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAzefbTApQ6jRKiJ0hcFyQeJAqwsFoZYRti3h0gpJhdaZOKMJ6F8KbuMmBLy2N
eumsoGst+RiznqgNipPEs+v3wUQsFB7fjME58Fxtop626hC3bCV8XGRWzRw1gEs0
tFqVCHlYC9ul8UQd/ynM29LzSHhBdUBlnCqQ+lLR6Cj2naOB5RWzImYm7nkB9Ff3
7cyHZZk9rszYNas4CpFEF/8CVp/7dujZHHl9x+GOrM9/sOWm4F3LKjMP5JvEQZUB
Dv5pkobLOLjgyEy51SLiYcQNCrsjRfSDRQGzqDWqwieid4/M/MKZSLtzC43u+ix1
YOr/iRKlHoZYFj1+rxbAEF/7dCY57CtDWD3upi4mcW8a2HkS2z4bM/nmx/9/BiG5
yiOa5YGRCiKgavLercxq9GUZbGPMYMObWgo64XIHbImWEZfTKPmtdquuJ7LI7kcT
rcufY2DuI+hEqHzoh5exfuubhXyda8v/0JRGIEfJYzSuZtVAxyeOjgEFjITMJaOL
+qDVaaJ/foVVrCRWzBmhvL+JnPNK9l0RZU0IBmxnAHS7m6tW4jda+h8/e/EH7l7/
tWCtW8KuZMcwQcZoBw70wfbzu2uHJXNA0KpIm6CH2b+DRO6OSQeSvTP+5IRG2IzX
1PmILkN6XfCZMk1yP/qBN1/4T0RKunLVr5AMuLqyRb8lQDECAwEAAaNWMFQwHQYD
VR0OBBYEFDoXFM6w6A08vcWWVIWV5+Xc7AtMMB8GA1UdIwQYMBaAFDoXFM6w6A08
vcWWVIWV5+Xc7AtMMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQAD
ggIBAEP4PYntQS4ep4PQuJ9ZEIh2K4GrNcClZ1AIMHmd8e2E+Lmz87GfKF34MX/w
DNBGgrehbj0vF7kJBj2xqaM1F7nj+g9V+gYxIWw7IMmvEu/OdPCOKrUlh+ZEn0fN
9/f/L3Te4VHfspENwOzdh2xXXaZaRkar7+dK1VFqfybyfd6X7SBhtLK7z96CuwhE
m5Np9vVo8Ns4GEY0MRhBmpyVS5U/ihUfFwK1HoAt0cM51/Mi9P324tz+oIayPnVM
+1LZ4rRkfrvfnG2d1vInamM06ar1TQuSQ9mUJZ/ZPbuuVDsjnFm4dcYc0IctHelO
RctIZX+gngAvVfk95h3E5dlWxK42Gg19dXrLzCCz1qxQ78gUv/yAP6nQtZ5cCwr3
6BJn81O2aCKg7zs1jvsovCZzj6VqCeujtOeJHyiiwcux3acCJUji1wVWDWf85KFv
ttW4GI24/8soI7asYBpVFUGGcXWlaK9Kyj+0Rx4VUXLZzvqFH5PUmsnNQqrkqCIW
vghNwzpDs5CyB0YllS72PqiErBnz1FOUTDZBK/SNzhbKh8M02WyzBEp3zGU5YXoD
R4VuZ06LY4pnjq7d51gj7wD9thc8k0JrEdtus39KIFI2Py1hyja7+jqttgt4yuwZ
nPgNSo9ViIrAO7PVmvJ8ikE7Bi9io4fFSA0Jzok+tx9WFpta
-----END CERTIFICATE-----`;

function extractBasicConstraintsExtension(certificate: string | Buffer) {
    certificate = coerceCertificate(certificate);
    const block_info = asn1.readTag(certificate, 0);
    const blocks = asn1.readStruct(certificate, block_info);
    const { extensions } = readTbsCertificate(certificate, blocks[0]);
    return extensions?.basicConstraints;
}

describe("Testing basicConstraint field", function (this) {
    it("Should parse if only CA:false is specified", async () => {
        const basicConstraints = extractBasicConstraintsExtension(CERT_1);

        if (basicConstraints) {
            assert(basicConstraints.cA === false);
        }
    });

    it("Should parse if only pathlen:0 is specified", async () => {
        const basicConstraints = extractBasicConstraintsExtension(CERT_2);

        if (basicConstraints) {
            assert(basicConstraints.pathLengthConstraint === 0);
        }
    });

    it("Should parse if both CA:false and pathlen:0 are specified", async () => {
        const basicConstraints = extractBasicConstraintsExtension(CERT_3);

        if (basicConstraints) {
            assert(basicConstraints.cA === false);
            assert(basicConstraints.pathLengthConstraint === 0);
        }
    });

    it("Should parse if both CA:true and pathlen:0 are specified", async () => {
        const basicConstraints = extractBasicConstraintsExtension(CERT_4);

        if (basicConstraints) {
            assert(basicConstraints.cA === true);
            assert(basicConstraints.pathLengthConstraint === 0);
        }
    });
});
