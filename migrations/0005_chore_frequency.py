# Generated by Django 3.0.3 on 2022-03-07 18:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('remember', '0004_auto_20220304_1721'),
    ]

    operations = [
        migrations.AddField(
            model_name='chore',
            name='frequency',
            field=models.FloatField(default=7.0),
        ),
    ]
