from django.contrib import admin
from .models import User, UserConfirmation


class UserModel(admin.ModelAdmin):
    list_display = ("id", )


class UserConfirmationAdmin(admin.ModelAdmin):
    list_display = ("id", )


admin.site.register(User, UserModel)
admin.site.register(UserConfirmation, UserConfirmationAdmin)