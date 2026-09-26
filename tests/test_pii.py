from kdeconnect_mcp.config import PhoneRedactionConfig, RedactionConfig
from kdeconnect_mcp.pii import Redactor


def make_redactor(**redaction_overrides) -> Redactor:
    cfg = RedactionConfig()
    for key, value in redaction_overrides.items():
        setattr(cfg, key, value)
    return Redactor(cfg)


def test_otp_bank_keyword_es():
    result = make_redactor().redact("BBVA: Tu codigo de autorizacion es 483920. No lo compartas.")
    assert "483920" not in result.text
    assert "[REDACTADO:otp]" in result.text
    assert result.categories == {"otp": 1}


def test_otp_with_accents():
    result = make_redactor().redact("Tu código de verificación es 1234")
    assert "1234" not in result.text
    assert result.categories.get("otp") == 1


def test_card_always_redacted():
    result = make_redactor().redact("Tarjeta 4111 1111 1111 1111")
    assert "4111" not in result.text
    assert result.categories.get("card") == 1


def test_dashed_order_number_is_card():
    result = make_redactor().redact("El pedido 407-1234567-8901234 va en camino.")
    assert "407-1234567-8901234" not in result.text


def test_iban_redacted():
    result = make_redactor().redact("Abono en ES91 2100 0418 4502 0005 1332 por 250 EUR")
    assert "ES91" not in result.text
    assert result.categories.get("iban") == 1


def test_phone_partial_masked():
    result = make_redactor().redact("Llama al +34 655 667 788 cuando puedas")
    assert "655667788" not in result.text
    assert "***788" in result.text
    assert result.categories.get("phone") == 1


def test_phone_full_mode():
    redactor = make_redactor(phone=PhoneRedactionConfig(mode="full"))
    result = redactor.redact("Llama al +34 655 667 788")
    assert "[REDACTADO:phone]" in result.text


def test_order_number_without_context_is_kept():
    text = "Tu pedido 12345678 va en camino"
    result = make_redactor().redact(text)
    assert result.text == text
    assert result.categories == {}


def test_sensitive_app_redacts_without_keyword():
    result = make_redactor().redact("Acceso: 555666", app="Google Authenticator")
    assert "555666" not in result.text
    assert result.categories.get("otp") == 1


def test_names_stay_visible():
    text = "Ana: ¿comemos el jueves?"
    result = make_redactor().redact(text, app="WhatsApp")
    assert result.text == text


def test_idempotent():
    redactor = make_redactor()
    first = redactor.redact("Tu codigo es 998877", app=None)
    second = redactor.redact(first.text, app=None)
    assert second.text == first.text
    assert second.categories == {}


def test_amount_near_keyword_is_redacted_conservatively():
    result = make_redactor().redact("Tu codigo ha sido enviado. Importe: 1.234,56 EUR")
    assert "1.234" not in result.text


def test_long_otp_redacted():
    result = make_redactor().redact("Codigo de autorizacion: 123456789")
    assert "123456789" not in result.text
    assert result.categories.get("otp") == 1


def test_date_not_otp():
    result = make_redactor().redact("Tu codigo caduca el 25-09-2026")
    assert "25-09-2026" in result.text


def test_mask_phone_partial_keeps_country_code():
    redactor = make_redactor()
    assert redactor.mask_phone("+34 600 123 456") == "+34 ***456"
    assert redactor.mask_phone("600123456") == "***456"


def test_multiple_categories_counted():
    result = make_redactor().redact(
        "Codigo 112233 y pago con 4111 1111 1111 1111"
    )
    assert result.categories.get("otp") == 1
    assert result.categories.get("card") == 1
