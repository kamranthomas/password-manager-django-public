# Generated by Django 4.2.11 on 2024-03-18 16:40

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0006_remove_userpassword_user_userpassword_users'),
    ]

    operations = [
        migrations.RenameField(
            model_name='userpassword',
            old_name='users',
            new_name='user',
        ),
    ]
