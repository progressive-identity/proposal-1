# ALIAS_PROTO = "https"
ALIAS_PROTO = "http"

# DEFAULT_KEY_ALGO = 'secp256k1'  # blockchain family
DEFAULT_KEY_ALGO = 'ed25519'    # djb family, smaller

DEFAULT_HASH = 'sha256'

DEFAULT_GRANT_TOKEN_TIMEOUT = None
DEFAULT_ACCESS_TOKEN_TIMEOUT = 1 * 60 * 60  # 1 hour
SUBKEY_EXPIRES_IN = 1 * 60 * 60     # 1 hour

DO_NOT_VERIFY_SSL = False
