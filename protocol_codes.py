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
    SEND_SHARED_KEY_REQUEST = "SKRQ"
    SEND_SHARED_KEY_RESPONSE = "SKRS"
    SELECT_ENCRYPTION_TYPE_REQUEST = "ETRQ"
    SELECT_ENCRYPTION_TYPE_RESPONSE = "ETRS"
    CHECK_ENCRYPTION_SUPPORT_REQUEST = "CERQ"
    CHECK_ENCRYPTION_SUPPORT_RESPONSE = "CERS"
    GET_RSA_PUBLIC_KEY_REQUEST = "RSRQ"
    GET_RSA_PUBLIC_KEY_RESPONSE = "RSRS"



