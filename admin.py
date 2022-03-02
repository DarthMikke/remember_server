from django.contrib import admin
from .models import Checklist, Chore, Record, Token

# Register your models here.
admin.site.register(Checklist)
admin.site.register(Chore)
admin.site.register(Record)
admin.site.register(Token)
