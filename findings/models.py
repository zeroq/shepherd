from django.db import models
from project.models import ActiveDomain

# Create your models here.

class Port(models.Model):
    """class to describe open ports
    """
    domain = models.ForeignKey(ActiveDomain, on_delete=models.CASCADE)
    domain_name = models.CharField(max_length=2048, default='')
    scan_date = models.DateTimeField(null=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=50, default='info')
    port = models.IntegerField()
    banner = models.CharField(max_length=2048, default='')
    status = models.CharField(max_length=50, default='open')
    product = models.CharField(max_length=2048, default='')
    cpe = models.CharField(max_length=2048, default='')
    raw = models.JSONField(null=True)

    def __str__(self):
        return "%i - %s - %s - %s" % (self.id, self.port, self.banner, self.domain.value)

class Finding(models.Model):
    """class to describe a security finding
    """
    domain = models.ForeignKey(ActiveDomain, on_delete=models.CASCADE)
    domain_name = models.CharField(max_length=2048, default='')

    # Finding details
    source = models.CharField(max_length=200, default='nuclei')
    name = models.CharField(max_length=2048, default='')
    type = models.CharField(max_length=2048, default='')
    url = models.CharField(max_length=2048, default='')
    description = models.TextField(default='')
    solution = models.TextField(default='')
    reference = models.CharField(max_length=2048, default='')

    # Severity fields
    severity = models.CharField(max_length=50, default='')
    cve = models.CharField(max_length=1024, default='')
    cvssscore = models.CharField(max_length=1024, default='')
    cvssmetrics = models.CharField(max_length=1024, default='')
    vulnerableAt = models.CharField(max_length=2048, default='')
    vulnerabilityDetails = models.CharField(max_length=4096, default='', blank=True, null=True)

    # Time related fields
    scan_date = models.DateTimeField(null=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_reported = models.DateTimeField(blank=True, null=True)

    reported = models.BooleanField(default=False)
    raw = models.JSONField(null=True)

    def __str__(self):
        return "%i - %s - %s - %s" % (self.id, self.name, self.severity, self.domain.value)
