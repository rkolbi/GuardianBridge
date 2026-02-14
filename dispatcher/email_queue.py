import logging

import gb_db
import settings


def queue_email_task(task):
    gb_db.add_outgoing_email(task)


def queue_sos_email_notification(sos_code, subject, body, extra_recipients=None):
    email_enabled_map = {
        "SOS": settings.SOS_EMAIL_ENABLED,
        "SOSM": settings.SOSM_EMAIL_ENABLED,
        "SOSF": settings.SOSF_EMAIL_ENABLED,
        "SOSP": settings.SOSP_EMAIL_ENABLED,
    }
    email_recipients_map = {
        "SOS": settings.SOS_EMAIL_RECIPIENTS,
        "SOSM": settings.SOSM_EMAIL_RECIPIENTS,
        "SOSF": settings.SOSF_EMAIL_RECIPIENTS,
        "SOSP": settings.SOSP_EMAIL_RECIPIENTS,
    }

    if not email_enabled_map.get(sos_code):
        return

    system_recipients = set(email_recipients_map.get(sos_code, []))
    user_recipients = extra_recipients if extra_recipients else set()
    final_recipients = list(system_recipients.union(user_recipients))

    if not final_recipients:
        logging.warning(f"SOS email for {sos_code} is enabled, but no recipients are configured.")
        return

    logging.info(f"Queueing SOS email notification to: {final_recipients}")
    for recipient in final_recipients:
        task = {
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "sender_node": "GuardianBridge",
            "is_sos": True,
        }
        gb_db.add_outgoing_email(task)
