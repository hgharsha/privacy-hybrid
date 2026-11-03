

def _locked_pdf(user_pw):
    import io
    from pypdf import PdfWriter
    w = PdfWriter()
    w.add_blank_page(200, 200)
    w.encrypt(user_pw, owner_password="owner")
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def test_encrypted_pdf_with_empty_user_password_opens_but_needs_password_otherwise():
    import pytest
    from privhybrid import ingest
    # blank page has no text, so an unlocked file reports "No text" (it got past the lock); a locked one asks for a password
    with pytest.raises(ingest.Unreadable, match="No text"):
        ingest.extract("a.pdf", _locked_pdf(""))
    with pytest.raises(ingest.Unreadable, match="Password needed"):
        ingest.extract("a.pdf", _locked_pdf("secret"))
    with pytest.raises(ingest.Unreadable, match="Wrong PDF password"):
        ingest.extract("a.pdf", _locked_pdf("secret"), "nope")
    with pytest.raises(ingest.Unreadable, match="No text"):
        ingest.extract("a.pdf", _locked_pdf("secret"), "secret")
