"""Envio de email: SMTP se SMTP_HOST estiver definido; caso contrário regista no log (dev)."""
import logging
import os
import smtplib
from email.message import EmailMessage

log = logging.getLogger("mailer")
outbox: list[tuple[str, str, str]] = []  # usado nos testes


def send_email(to: str, subject: str, body: str) -> None:
    host = os.environ.get("SMTP_HOST")
    if not host:
        outbox.append((to, subject, body))
        del outbox[:-100]  # só em dev: evita crescimento ilimitado
        log.info("EMAIL (dev) para=%s assunto=%s", to, subject)
        return
    msg = EmailMessage()
    msg["From"] = os.environ.get("SMTP_FROM", "no-reply@example.com")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587"))) as s:
        s.starttls()
        if os.environ.get("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        s.send_message(msg)
