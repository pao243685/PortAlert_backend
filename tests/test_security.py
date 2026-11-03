from app.core.security import (
    create_access_token,
    create_mfa_token,
    decode_access_token,
    decode_mfa_token,
    decrypt_secret,
    encrypt_secret,
)


def test_secreto_se_cifra_y_se_descifra():
    cifrado = encrypt_secret("JBSWY3DPEHPK3PXP")
    assert "JBSWY3DPEHPK3PXP" not in cifrado
    assert decrypt_secret(cifrado) == "JBSWY3DPEHPK3PXP"


def test_token_de_sesion_y_token_mfa_no_se_intercambian():
    assert decode_access_token(create_access_token(7)) == 7
    assert decode_mfa_token(create_mfa_token(7)) == 7
    assert decode_access_token(create_mfa_token(7)) is None
    assert decode_mfa_token(create_access_token(7)) is None
