from django.db import models

# Create your models here.

class Project(models.Model):
    """Class describes a project or company that we want to monitor
    """
    projectname = models.CharField(max_length=1024, unique=True)
    description = models.TextField(default='')
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "%s" % (self.projectname)

class Keyword(models.Model):
    """Keyword describing a company (can be the name)
    """
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    keyword = models.CharField(max_length=1024)  # keyword to use as a starting point
    description = models.TextField(default='')
    enabled = models.BooleanField(default=True)  # disable keywords that should not be used
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    ktype = models.CharField(max_length=1024, default='registrant_org')  # what type of keyword, e.g. name, domain, ...

    def __str__(self):
        return "%s" % (self.keyword)

class Suggestion(models.Model):
    """Potentially fitting domains for project
    """
    related_keyword = models.ForeignKey("Keyword", on_delete=models.CASCADE)
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    finding_type = models.CharField(max_length=100, default='domain')  # can be: domain, ip, url, certificate
    finding_subtype = models.CharField(max_length=100, default='subdomain')  # can be: domain, subdomain
    value = models.CharField(max_length=2048, default='')
    uuid = models.CharField(max_length=36, primary_key=True)
    source = models.CharField(max_length=200, default='')  # can be cert.sh for example
    creation_time = models.DateTimeField()  # when was it found to be created
    description = models.TextField(default='')
    link = models.CharField(max_length=1024, default='', blank=True)
    cert_valid = models.BooleanField(default=True)
    cert_wildcard = models.BooleanField(default=False)
    ignore = models.BooleanField(default=False) # ignore these findings in the future (set to invisible and ignore if it shows up again)
    is_monitored = models.BooleanField(default=False) # ignore these findings as they are already on the monitoring list
    raw = models.JSONField(null=True, default=None)
    
    def __str__(self):
        return "%s - %s" % (self.finding_type, self.value)

class ActiveDomain(models.Model):
    """Active Domains for monitoring
    """
    related_keyword = models.ForeignKey("Keyword", on_delete=models.CASCADE)
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    finding_subtype = models.CharField(max_length=100, default='domain')  # can be: domain, subdomain
    value = models.CharField(max_length=2048, default='')
    uuid = models.CharField(max_length=36, primary_key=True)
    source = models.CharField(max_length=200, default='')  # can be cert.sh for example
    creation_time = models.DateTimeField()  # when was it found to be created
    lastscan_time = models.DateTimeField(blank=True, null=True)  # when was it last scanned
    description = models.TextField(default='')
    link = models.CharField(max_length=1024, default='', blank=True)
    monitor = models.BooleanField(default=True) # monitor this item
    
    def __str__(self):
        return "%s - %s" % (self.value, self.source)

class ActiveIP(models.Model):
    """Active IPs for monitoring
    """
    related_keyword = models.ForeignKey("Keyword", on_delete=models.CASCADE)
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    value = models.CharField(max_length=2048, default='')
    uuid = models.CharField(max_length=36, primary_key=True)
    source = models.CharField(max_length=200, default='')  # can be cert.sh for example
    creation_time = models.DateTimeField()  # when was it found to be created
    lastscan_time = models.DateTimeField(blank=True, null=True)  # when was it last scanned
    description = models.TextField(default='')
    link = models.CharField(max_length=1024)
    monitor = models.BooleanField(default=True) # monitor this item

class ActiveCertificate(models.Model):
    """Active Certificates for monitoring
    """
    related_keyword = models.ForeignKey("Keyword", on_delete=models.CASCADE)
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    value = models.CharField(max_length=2048, default='')
    uuid = models.CharField(max_length=36, primary_key=True)
    source = models.CharField(max_length=200, default='')  # can be cert.sh for example
    creation_time = models.DateTimeField()  # when was it found to be created
    description = models.TextField(default='')
    link = models.CharField(max_length=1024)
    cert_valid = models.BooleanField(default=True)
    cert_wildcard = models.BooleanField(default=False)
    monitor = models.BooleanField(default=True) # monitor this item


class RelatedIP(models.Model):
    related_domains = models.ForeignKey("ActiveDomain", on_delete=models.CASCADE)
    ip = models.GenericIPAddressField()


class RelatedDomain(models.Model):
    related_ips = models.ForeignKey("ActiveIP", on_delete=models.CASCADE)
    domain = models.CharField(max_length=2048, default='')
