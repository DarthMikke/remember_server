from django.contrib import admin
from .models import Checklist, Chore, Record, Token


class TokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'token']


# Register your models here.
admin.site.register(Checklist)
admin.site.register(Chore)
admin.site.register(Record)
admin.site.register(Token, TokenAdmin)
