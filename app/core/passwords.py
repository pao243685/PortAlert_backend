"""Política de contraseñas del registro (el login NO la aplica, para no bloquear cuentas existentes)."""
MIN_LENGTH = 8
MAX_BYTES = 72  # límite real de bcrypt: lo que pase de 72 bytes se ignoraría (o falla, según la versión)

# Contraseñas muy comunes. Se comparan en minúsculas y sin los números/símbolos del final.
_BASES_COMUNES = {
    "password", "contraseña", "contrasena", "qwerty", "qwertyuiop", "admin", "administrator", "welcome",
    "letmein", "iloveyou", "clave", "abc", "monkey", "dragon", "master", "login", "portalert", "test", "usuario",
}
_COMPLETAS_COMUNES = {"12345678", "123456789", "1234567890", "qwerty123", "abc12345", "11111111", "00000000"}


def _es_especial(c: str) -> bool:
    return not c.isalnum() and not c.isspace()


def problems(password: str, email: str | None = None) -> list[str]:
    """Lista de requisitos que NO cumple (vacía = la contraseña es válida)."""
    out: list[str] = []
    if len(password) < MIN_LENGTH:
        out.append(f"al menos {MIN_LENGTH} caracteres")
    if not any(c.isupper() for c in password):
        out.append("una letra mayúscula")
    if not any(c.islower() for c in password):
        out.append("una letra minúscula")
    if not any(c.isdigit() for c in password):
        out.append("un número")
    if not any(_es_especial(c) for c in password):
        out.append("un carácter especial (por ejemplo ! ? # $ % & * @)")
    if len(password.encode("utf-8")) > MAX_BYTES:
        out.append(f"como máximo {MAX_BYTES} bytes (los acentos y emojis cuentan más de uno)")
    if password != password.strip():
        out.append("sin espacios al principio ni al final")
    base = password.lower().rstrip("0123456789!@#$%^&*()_+-=.,;:?¿¡ ")
    if password.lower() in _COMPLETAS_COMUNES or base in _BASES_COMUNES:
        out.append("no ser una contraseña común")
    local = (email or "").split("@")[0].lower()
    if len(local) >= 4 and local in password.lower():
        out.append("no contener tu correo")
    return out
