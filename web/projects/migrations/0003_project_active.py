# Generated by Django 4.2.3 on 2024-03-30 15:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("projects", "0002_alter_project_name"),
    ]

    operations = [
        migrations.AddField(
            model_name="project",
            name="active",
            field=models.BooleanField(default=True),
        ),
    ]
