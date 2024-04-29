from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings


def send_account_activation_email(recipient_email, activation_url):
    subject = f'Activate your account on {settings.SITE_NAME}'
    from_email = settings.EMAIL_HOST_USER
    to = [recipient_email]

    # load the html template
    html_content = render_to_string('account/activation_email.html',
                                    {'activation_url': activation_url})

    #  Create the email body with both HTML and plain text version

    text_content = strip_tags(html_content)
    email = EmailMultiAlternatives(subject, text_content, from_email, to)
    email.attach_alternative(html_content, "text/html")
    email.send()


def send_reset_password_email(recipient_email, password_reset_url):
    subject = f'Rest your password on {settings.SITE_NAME}'
    from_email = settings.EMAIL_HOST_USER
    to = [recipient_email]

    # load the html template
    html_content = render_to_string('account/reset_password_email.html',
                                    {'password_reset_url': password_reset_url})

    #  Create the email body with both HTML and plain text version

    text_content = strip_tags(html_content)
    email = EmailMultiAlternatives (subject, text_content, from_email, to)
    email.attach_alternative (html_content, "text/html")
    email.send ()