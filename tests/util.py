from __future__ import absolute_import, division, print_function

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from service_identity.cryptography import extract_ids

# Test certificates

PEM_DNS_ONLY = b"""\
-----BEGIN CERTIFICATE-----
MIIGbjCCBVagAwIBAgIDCesrMA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJJ
TDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0
YWwgQ2VydGlmaWNhdGUgU2lnbmluZzE4MDYGA1UEAxMvU3RhcnRDb20gQ2xhc3Mg
MSBQcmltYXJ5IEludGVybWVkaWF0ZSBTZXJ2ZXIgQ0EwHhcNMTMwNDEwMTk1ODA5
WhcNMTQwNDExMTkyODAwWjB1MRkwFwYDVQQNExBTN2xiQ3Q3TjJSNHQ5bzhKMQsw
CQYDVQQGEwJVUzEeMBwGA1UEAxMVd3d3LnR3aXN0ZWRtYXRyaXguY29tMSswKQYJ
KoZIhvcNAQkBFhxwb3N0bWFzdGVyQHR3aXN0ZWRtYXRyaXguY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxUH8iDxIEiDcMQb8kr/JTYXDGuE8ISQA
uw/gBqpvHIvCgPBkZpvjQLA23rnUZm1S3VG5MIq6gZVdtl9LFIfokMPGgY9EZng8
BaI+6Y36cMtubnzW53OZb7yLQQyg+rjuwjvJOY33ZulEthxhdB3km1Leb67iE9v7
dpyKeJ/8m2IWD37HCtXIEnp9ZqWOZkAPzlzDt6oNxj0s/l3z23+XqZdr+kmlh9U+
VWBTPppO4AJNwSqbBd0PgIozbYsp6urxSr40YQkIYFOOZQNs7HETJE71Ia7DQcUD
kUF1jZSYZnhVQwGPisqQLGodt9q9p2BhpSf0cUm02uKKzYi5A2h7UQIDAQABo4IC
7TCCAukwCQYDVR0TBAIwADALBgNVHQ8EBAMCA6gwEwYDVR0lBAwwCgYIKwYBBQUH
AwEwHQYDVR0OBBYEFGeuUvDrFHkl7Krl/+rlv1FsnsU6MB8GA1UdIwQYMBaAFOtC
NNCYsKuf9BtrCPfMZC7vDixFMDMGA1UdEQQsMCqCFXd3dy50d2lzdGVkbWF0cml4
LmNvbYIRdHdpc3RlZG1hdHJpeC5jb20wggFWBgNVHSAEggFNMIIBSTAIBgZngQwB
AgEwggE7BgsrBgEEAYG1NwECAzCCASowLgYIKwYBBQUHAgEWImh0dHA6Ly93d3cu
c3RhcnRzc2wuY29tL3BvbGljeS5wZGYwgfcGCCsGAQUFBwICMIHqMCcWIFN0YXJ0
Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MAMCAQEagb5UaGlzIGNlcnRpZmlj
YXRlIHdhcyBpc3N1ZWQgYWNjb3JkaW5nIHRvIHRoZSBDbGFzcyAxIFZhbGlkYXRp
b24gcmVxdWlyZW1lbnRzIG9mIHRoZSBTdGFydENvbSBDQSBwb2xpY3ksIHJlbGlh
bmNlIG9ubHkgZm9yIHRoZSBpbnRlbmRlZCBwdXJwb3NlIGluIGNvbXBsaWFuY2Ug
b2YgdGhlIHJlbHlpbmcgcGFydHkgb2JsaWdhdGlvbnMuMDUGA1UdHwQuMCwwKqAo
oCaGJGh0dHA6Ly9jcmwuc3RhcnRzc2wuY29tL2NydDEtY3JsLmNybDCBjgYIKwYB
BQUHAQEEgYEwfzA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Auc3RhcnRzc2wuY29t
L3N1Yi9jbGFzczEvc2VydmVyL2NhMEIGCCsGAQUFBzAChjZodHRwOi8vYWlhLnN0
YXJ0c3NsLmNvbS9jZXJ0cy9zdWIuY2xhc3MxLnNlcnZlci5jYS5jcnQwIwYDVR0S
BBwwGoYYaHR0cDovL3d3dy5zdGFydHNzbC5jb20vMA0GCSqGSIb3DQEBBQUAA4IB
AQCN85dUStYjHmWdXthpAqJcS3KD2JP6N9egOz7FTcToXLW8Kl5a2SUVaJv8Fzs+
wtbPJQSm0LyGtfdrR6iKFPf28Vm/VkYXPiOV08GD9B7yl1SjktXOsGMPlOHU8YQZ
DEsHOrRvaZBSA1VtBQjYnoO0pDVu9QwDLAPLFvFice2PN803HuMFIwcuQSIrh4nq
PqwitBZ6nPPHz7aSiAut/+txK3EZll0d+hl0H3Phd+ICeITYhNkLe90k7l1IFpET
fJiBDvG/iDAJISgkrR1heuX/e+yWfx7RvqGlMLIE35d+0MhWy92Jzejbl8fJdr4C
Kulh/pV07MWAUZxscUPtWmPo
-----END CERTIFICATE-----"""

DNS_IDS = extract_ids(
    load_pem_x509_certificate(PEM_DNS_ONLY, default_backend())
)

PEM_CN_ONLY = b"""\
-----BEGIN CERTIFICATE-----
MIIGdDCCBVygAwIBAgIKGOC4tAABAAAx0TANBgkqhkiG9w0BAQUFADCBgDETMBEG
CgmSJomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEUMBIG
CgmSJomT8ixkARkWBGNvcnAxFzAVBgoJkiaJk/IsZAEZFgdyZWRtb25kMR8wHQYD
VQQDExZNU0lUIE1hY2hpbmUgQXV0aCBDQSAyMB4XDTEzMDExMjAwMDc0MVoXDTE1
MDExMjAwMDc0MVoweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQH
EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDjAMBgNV
BAsTBU1TQ09NMRowGAYDVQQDExF3d3cubWljcm9zb2Z0LmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAJ+h4bQ7OlcO0M9UvM0Y2LISEzGkTDc9CT7v
c91kI2GOlR/kbI1AUmJu3g6Cv0wqz4b9QT6BdXSE+WAxUM/yk4mf1HhkJtbSwucb
AQAtgq0iC1u6mDDXH2sl/NUB4VKSGryIYYdRVHduZlFkAHmxwcmxyQt6BQykXl7G
NkftiJZtVci/ZRPaBrFnkZjZCbJH+capx0v9hmBTLPVAGyIF5TwF1aldXT367S76
QGGn6UnI0O5Cua7GU1JDVmbPus0kgRTazvyW4g17jGFtNJTy43UqlX7TZ8B76OZC
sqoVxJblVh7I0WDcDFwIrSWiUEFc9i05g1g49xK8Y7tph8tbwv8CAwEAAaOCAvUw
ggLxMAsGA1UdDwQEAwIEsDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUK9tKP5ACSJ4PiSHi
60pzHuAPhWswHwYDVR0jBBgwFoAU69sRXvgJntjWYpz9Yp3jhEoo4Scwge4GA1Ud
HwSB5jCB4zCB4KCB3aCB2oZPaHR0cDovL21zY3JsLm1pY3Jvc29mdC5jb20vcGtp
L21zY29ycC9jcmwvTVNJVCUyME1hY2hpbmUlMjBBdXRoJTIwQ0ElMjAyKDEpLmNy
bIZNaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9tc2NvcnAvY3JsL01TSVQl
MjBNYWNoaW5lJTIwQXV0aCUyMENBJTIwMigxKS5jcmyGOGh0dHA6Ly9jb3JwcGtp
L2NybC9NU0lUJTIwTWFjaGluZSUyMEF1dGglMjBDQSUyMDIoMSkuY3JsMIGtBggr
BgEFBQcBAQSBoDCBnTBVBggrBgEFBQcwAoZJaHR0cDovL3d3dy5taWNyb3NvZnQu
Y29tL3BraS9tc2NvcnAvTVNJVCUyME1hY2hpbmUlMjBBdXRoJTIwQ0ElMjAyKDEp
LmNydDBEBggrBgEFBQcwAoY4aHR0cDovL2NvcnBwa2kvYWlhL01TSVQlMjBNYWNo
aW5lJTIwQXV0aCUyMENBJTIwMigxKS5jcnQwPwYJKwYBBAGCNxUHBDIwMAYoKwYB
BAGCNxUIg8+JTa3yAoWhnwyC+sp9geH7dIFPg8LthQiOqdKFYwIBZAIBCjAnBgkr
BgEEAYI3FQoEGjAYMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEB
BQUAA4IBAQBgwMY9qix/FoBY3QBHTNFVf+d6siaBWoQjwBXDQlPXLmowbt97j62Z
N6OogRP2V+ivnBcybucJTJE6zTxrGZ7hNeC9T3v34Q1OMezWiZf+jktNZvqiXctm
Dh774lt5S9X2C+k1e9K8YrnNb8PNeKkX/vVX9MZzn2aQqU34dOg6vVnrq0pBrq/Y
TJcPG4yq3kFR3ONTZb5JgE8EV1G43vW/LNQbEbQUgVtiKRapEs7rSSws6Jj47MUc
on6HgPTtfuJGMNWFTiw7nZTM8mLXsXBMePSgq8PkKPmPkB3KET/OitmePmhk4l+S
eMkNCM6YlrLcDF4fCLSjWYhoktmSJZnW
-----END CERTIFICATE-----
"""


PEM_OTHER_NAME = b"""\
-----BEGIN CERTIFICATE-----
MIID/DCCAuSgAwIBAgIJAIS0TSddIw6cMA0GCSqGSIb3DQEBBQUAMGwxFDASBgNV
BAMTC2V4YW1wbGUuY29tMSAwHgYJKoZIhvcNAQkBFhFib2d1c0BleGFtcGxlLmNv
bTEUMBIGA1UEChMLRXhhbXBsZSBJbmMxDzANBgNVBAcTBkJlcmxpbjELMAkGA1UE
BhMCREUwHhcNMTQwMzA2MTYyNTA5WhcNMTUwMzA2MTYyNTA5WjBsMRQwEgYDVQQD
EwtleGFtcGxlLmNvbTEgMB4GCSqGSIb3DQEJARYRYm9ndXNAZXhhbXBsZS5jb20x
FDASBgNVBAoTC0V4YW1wbGUgSW5jMQ8wDQYDVQQHEwZCZXJsaW4xCzAJBgNVBAYT
AkRFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGQUcOc8cAdzSJbk
0eCHA1qBY2XwRG8YQzihgQS8Ey+3j69Xf0mtWOlL6v23v8J1ilA7ERs87Y4nbV/9
GJVhC/jTMZmrC6ogwtVIl1wL8sTiHaQZ/4pbpx57YW3qCdefLQrZqAMUgAe20z0G
YVU97u5EGXHYahG4TnB3xN6Qd3BGKP7K69Lb7ZOES2Esq533AZxZShseYR4JNYAc
2anag2/DpHw6k8ZaxtWHR4SmxlkCoW5IPK0YypeUY91PFY+dxJQEewtisfALKltE
SYnOTWkc0K9YuLuYVogx0K285wX4/Yha2wyo6KSAm0txJayOhcrEP2/34aWCl62m
xOtPbQIDAQABo4GgMIGdMIGaBgNVHREEgZIwgY+CDSouZXhhbXBsZS5uZXSCC2V4
YW1wbGUuY29thwTAqAABhxAAEwAAAAAAAAAAAAAAAAAXhhNodHRwOi8vZXhhbXBs
ZS5jb20voCYGCCsGAQUFBwgHoBoWGF94bXBwLWNsaWVudC5leGFtcGxlLm5ldKAc
BggrBgEFBQcIBaAQDA5pbS5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQUFAAOCAQEA
ACVQcgEKzXEw0M9mmVFFXL2SyDk/4oaDFZbnNfyUp+H7bnxdVBG2M3DzQQLw5yH5
k4GNPvHOKshBbaFcZWiG1sdrfQJy/UjIWnaC5410npfBv7kJWafKKxZzMq3gp4rd
jPO2LxuWcYVOnUtA3CBe12tRV7ynGU8KmKOsU9bOWhUKo8DJ4a6XHB+YwXeOTPyU
mG7XBpQebT01I3OijFJ+apKR2ubjwZE8l1+BAlTzHyUmmcTTWTQk8FTFcP3nZuIr
VyudDBMASs4yVGHzQxmMalYYzd7ZDzM1NrgfG1KyKWqZEA0MzUxiYdUbZN79xL52
EyKUOXPHw78G6zsVmAE1Aw==
-----END CERTIFICATE-----"""
