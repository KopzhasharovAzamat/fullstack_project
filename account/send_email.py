from django.core.mail import send_mail 
from decouple import config 
 
 
def send_confirmation_email(user, code): 
    send_mail( 
        'Hello! Activate your account!', 
        f'code: {code}', 
        config('EMAIL_USER'), 
        [user], 
        fail_silently=False 
    )