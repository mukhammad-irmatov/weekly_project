import re
from rest_framework.exceptions import ValidationError

email_regex = re.compile(r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])")
phone_regex = re.compile(r"^9\d{12}$")
username_regex = r"^[a-zA-Z0-9_-]+$"


def check_email_or_phone(email_or_phone):
    if re.fullmatch(email_regex, email_or_phone):
        email_or_phone = "email"
    elif re.fullmatch(phone_regex, email_or_phone):
        email_or_phone = "phone"
    else:
        data = {
            "success": False,
            'message': "Email yoki telefon raqamingiz notog'ri"
        }
        raise ValidationError(data)

    return email_or_phone


def check_user_type(user_input):
    if re.fullmatch(email_regex, user_input):
        user_input = "email"
    elif re.fullmatch(phone_regex, user_input):
        user_input = "phone"
    elif re.fullmatch(username_regex, user_input):
        user_input = "username"
    else:
        data = {
            "success": False,
            'message': "Email, username yoki telefon raqamingiz notog'ri"
        }
        raise ValidationError(data)

    return user_input