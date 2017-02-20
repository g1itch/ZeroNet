import base64
import hashlib

import logging

try:
    import rsa
except ImportError:
    logging.info("No system rsa, importing bundled")
    from lib import rsa


def sign(data, privatekey):

    if "BEGIN RSA PRIVATE KEY" not in privatekey:
        privatekey = "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----" % privatekey

    priv = rsa.PrivateKey.load_pkcs1(privatekey)
    sign = rsa.pkcs1.sign(data, priv, 'SHA-256')
    return sign

def verify(data, publickey, sign):

    pub = rsa.PublicKey.load_pkcs1(publickey, format="DER")
    try:
        valid = rsa.pkcs1.verify(data, sign, pub)
    except rsa.pkcs1.VerificationError:
        valid = False
    return valid

def privatekeyToPublickey(privatekey):

    if "BEGIN RSA PRIVATE KEY" not in privatekey:
        privatekey = "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----" % privatekey

    priv = rsa.PrivateKey.load_pkcs1(privatekey)
    pub = rsa.PublicKey(priv.n, priv.e)
    return pub.save_pkcs1("DER")

def publickeyToOnion(publickey):
    return base64.b32encode(hashlib.sha1(publickey).digest()[:10]).lower()
