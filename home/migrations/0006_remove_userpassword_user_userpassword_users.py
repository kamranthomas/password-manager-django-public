# Generated by Django 4.2.11 on 2024-03-18 16:36

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('home', '0005_userpassword_user_created_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userpassword',
            name='user',
        ),
        migrations.AddField(
            model_name='userpassword',
            name='users',
            field=models.ManyToManyField(related_name='passwords', to=settings.AUTH_USER_MODEL),
        ),
    ]
