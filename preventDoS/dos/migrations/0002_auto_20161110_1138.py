# -*- coding: utf-8 -*-
# Generated by Django 1.10.3 on 2016-11-10 11:38
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dos', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='permanentblockip',
            name='ip_address',
            field=models.CharField(max_length=200, unique=True, verbose_name='IP Adress'),
        ),
    ]
