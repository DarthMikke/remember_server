# Generated by Django 3.2.5 on 2022-03-12 12:00

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('remember', '0008_alter_token_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='token',
            name='profile',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='remember.profile'),
        ),
    ]
