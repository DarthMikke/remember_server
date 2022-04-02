from django.db import models
from django.contrib.auth.models import User

import uuid
from datetime import datetime


# Create your models here.
class Profile(models.Model):
    AUTH_CHOICES = [
        ('password', 'password'),
        ('google', 'Google'),
        ('apple', 'Apple'),
    ]
    authentication = models.CharField(max_length=200, choices=AUTH_CHOICES, default='password')
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    google = models.CharField(max_length=200, null=True, blank=True)
    apple = models.CharField(max_length=200, null=True, blank=True)

    name = models.CharField(max_length=200, null=True, blank=True)

    def checklists(self):
        return Checklist.objects.filter(
            models.Q(owner=self) | models.Q(shared_with=self)
        )

    def __str__(self):
        return self.name

    def as_dict(self):
        return {
            'id': self.id,
            'user': self.user.id,
            'authentication': self.authentication,
            'name': self.name
        }

    @staticmethod
    def from_user(user):
        """
        Generate a profile from user
        """
        instance = Profile.objects.create(
            authentication='password',
            user=user,
            name=user.username
        )
        return instance


class Checklist(models.Model):
    owner_old = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    owner = models.ForeignKey(Profile, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=200)
    shared_with = models.ManyToManyField(Profile, related_name='shared_lists', blank=True)

    # Actions
    def add_chore(self, name, frequency):
        instance = Chore.objects.create(list=self, name=name, frequency=frequency)
        return instance

    def share_with(self, profile_id: int):
        """
        Share with a profile with a given id
        @param profile_id: Profile's id
        """
        try:
            profile = Profile.objects.get(id=profile_id)
        except Profile.DoesNotExist:
            return False

        self._share_with(profile)
        return True

    def _share_with(self, profile: Profile):
        self.shared_with.add(profile)
        self.save()

    def unshare_with(self, profile_id):
        """
        Remove a profile with a given id from self.shared_with
        @param profile_id: Profile's id
        """
        try:
            profile = Profile.objects.get(id=profile_id)
        except Profile.DoesNotExist:
            return False

        self.shared_with.remove(profile)
        profile.save()
        self.save()
        return True

    def is_accessible_by(self, profile: Profile):
        """
        Is the checklist accessible for a given profile?
        @param profile: Profile
        """
        if self.owner == profile:
            return True
        if profile.id in [x.id for x in self.shared_with.all()]:
            return True
        return False

    # Read properties
    def as_dict(self):
        return {
            'id': self.id,
            'owner': self.owner.id,
            'name': self.name,
            'items': [x.id for x in self.chore_set.all()],
            'shared_with': [x.id for x in self.shared_with.all()]
        }

    def as_deep_dict(self):
        base = self.as_dict()
        base['owner'] = self.owner.as_dict()
        base['items'] = [x.as_dict() for x in self.chore_set.all()]
        base['shared_with'] = [x.as_dict() for x in self.shared_with.all()]
        return base

    def __str__(self):
        return f"{self.name} ({self.owner})"


class Chore(models.Model):
    name = models.CharField(max_length=200)
    list = models.ForeignKey(Checklist, on_delete=models.CASCADE)
    frequency = models.FloatField(default=7.0)

    # Actions
    def log(self, dtg=datetime.now(), note=""):
        new_entry = Record.objects.create(chore=self, timestamp=dtg)
        return new_entry

    # Read properties
    def last(self) -> datetime or None:
        """
        Return last time this task was logged.
        @returns datetime|None
        """
        if len(self.record_set.all()) == 0:
            return None

        return self.ordered_logs()[0].timestamp

    def ordered_logs(self):
        return self.record_set.order_by('-timestamp')

    def as_dict(self):
        return {
            'id': self.id,
            'frequency': self.frequency,
            'name': self.name,
            'list': self.list.id,
            'last_logged': self.last()
        }

    def as_deep_dict(self):
        base_dict = self.as_dict()
        base_dict['logs'] = [x.as_dict() for x in self.ordered_logs()]
        return base_dict

    def __str__(self):
        return self.name


class Record(models.Model):
    chore = models.ForeignKey(Chore, on_delete=models.CASCADE)
    timestamp = models.DateTimeField()
    logged_by = models.ForeignKey(Profile, on_delete=models.SET_NULL, null=True, blank=True)

    def as_dict(self):
        return {
            'id': self.id,
            'chore': self.chore.id,
            'timestamp': self.timestamp.isoformat(),
            'note': '',
            'logged_by': None if self.logged_by is None else self.logged_by.as_dict()
        }

    def __str__(self):
        return f"{self.chore} @ {self.timestamp}"


class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, null=True, blank=True)
    token = models.UUIDField(default=uuid.uuid4)

    def __str__(self):
        user_string = f"user {self.user.username}" if self.user is not None else f"profile {self.profile}"
        return f"Token {self.token} for {user_string}"


def generate_token(user: User) -> Token:
    """
    @deprecated since migration 0009
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


def generate_profile_token(profile: Profile) -> Token:
    """
    @params profile: Profile to create token for
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

    return Token.objects.create(profile=profile, token=token)
