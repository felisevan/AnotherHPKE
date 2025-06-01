from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

HPKEXCurvePrivateKey = X25519PrivateKey | X448PrivateKey
HPKEXCurvePublicKey = X25519PublicKey | X448PublicKey

HPKEPrivateKeyTypes = EllipticCurvePrivateKey | HPKEXCurvePrivateKey
HPKEPublicKeyTypes = EllipticCurvePublicKey | HPKEXCurvePublicKey
