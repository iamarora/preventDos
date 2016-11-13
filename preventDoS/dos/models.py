from __future__ import unicode_literals

from django.db import models

# Create your models here.
class PermanentBlockIp(models.Model):
    ip_address = models.CharField('IP Adress', blank=False, null=False, unique=True, max_length=200)

    def __unicode__(self):
        return self.ip_address
