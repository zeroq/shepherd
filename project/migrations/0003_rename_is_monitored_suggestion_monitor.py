# Generated by Django 5.1.7 on 2025-03-17 10:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('project', '0002_alter_suggestion_active'),
    ]

    operations = [
        migrations.RenameField(
            model_name='suggestion',
            old_name='is_monitored',
            new_name='monitor',
        ),
    ]
