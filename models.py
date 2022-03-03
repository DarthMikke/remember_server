from django.db import models
from django.contrib.auth.models import User

import uuid
from datetime import datetime


# Create your models here.
class Checklist(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)

    def add_chore(self, name):
        instance = Chore.objects.create(list=self, name=name)
        return instance

    def as_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'items': [x.id for x in self.chore_set.all()],
        }

    def as_deep_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'items': [x.as_dict() for x in self.chore_set.all()],
        }

    def __str__(self):
        return f"{self.name} ({self.owner})"


class Chore(models.Model):
    name = models.CharField(max_length=200)
    list = models.ForeignKey(Checklist, on_delete=models.CASCADE)

    def log(self, dtg=datetime.now()):
        new_entry = Record.objects.create(chore=self, timestamp=dtg)
        return new_entry

    def last(self):
        if len(self.record_set.all()) == 0:
            return None

        return self.record_set.last().timestamp

    def as_dict(self):
        return {'id': self.id, 'name': self.name, 'list': self.list.id, 'last_logged': self.last()}

    def as_deep_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'list': self.list.id,
            'last_logged': self.last(),
            'logs': [x.as_dict() for x in self.record_set.all()],
        }

    def __str__(self):
        return self.name


class Record(models.Model):
    chore = models.ForeignKey(Chore, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now=True)

    def as_dict(self):
        return {
            'id': self.id,
            'chore': self.chore.id,
            'timestamp': self.timestamp.isoformat(),
            'note': ''
        }

    def __str__(self):
        return f"{self.chore} @ {self.timestamp}"


class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4)


def generate_token(user: User) -> Token:
    """
    @params user: User to create token for
    @returns Token
    """
    # TODO: revoke previous tokens?

    exists = True
    token = None
    while exists:
        token = uuid.uuid4()
        try:
            token_instance = Token.objects.get(token=token)
        except Token.DoesNotExist:
            exists = False

    return Token.objects.create(user=user, token=token)
