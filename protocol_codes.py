from enum import Enum


class ProtocolCodes(Enum):
    LOGIN_REQUEST = "LGRQ"
    LOGIN_RESPONSE = "LGRS"
    SIGN_UP_REQUEST = "SNRQ"
    SIGN_UP_RESPONSE = "SNRS"
    FORGOT_PASSWORD_REQUEST = "FPRQ"
    FORGOT_PASSWORD_RESPONSE = "FPRS"
    VERIFY_SIGN_UP_REQUEST = "VSRQ"
    VERIFY_SIGN_UP_RESPONSE = "VSRS"
    RESEND_VERIFICATION_CODE_REQUEST = "RVRQ" #לייצר מחדש קוד אם נגמר הזמן של הקוד הקודם
    RESEND_VERIFICATION_CODE_RESPONSE = "RVRS"
    RESET_PASSWORD_REQUEST = "RPRQ"
    RESET_PASSWORD_RESPONSE = "RPRS"
    RSA_AES_KEY_EXCHANGE_REQUEST = "RARQ"
    AES_KEY_EXCHANGE_RESPONSE = "AXRS"
    SELECT_ENCRYPTION_TYPE_REQUEST = "ETRQ"
    SELECT_ENCRYPTION_TYPE_RESPONSE = "ETRS"
    CHECK_ENCRYPTION_SUPPORT_REQUEST = "CERQ"
    CHECK_ENCRYPTION_SUPPORT_RESPONSE = "CERS"
    RSA_PUBLIC_KEY_REQUEST = "RSRQ"
    RSA_PUBLIC_KEY_RESPONSE = "RSRS"
    DH_CLIENT_PUB_KEY_REQUEST = "DPRQ"
    DH_CLIENT_PUB_KEY_RESPONSE = "DPRS"
    DH_AES_KEY_EXCHANGE_REQUEST = "DARQ"




