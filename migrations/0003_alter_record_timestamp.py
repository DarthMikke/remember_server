# Generated by Django 3.2.5 on 2022-03-03 20:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('remember', '0002_alter_token_token'),
    ]

    operations = [
        migrations.AlterField(
            model_name='record',
            name='timestamp',
            field=models.DateTimeField(),
        ),
    ]
