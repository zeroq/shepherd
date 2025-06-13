
from rest_framework import serializers

from project.models import Job, Project, Keyword, Suggestion, ActiveDomain
from findings.models import Finding, Port, Screenshot

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = '__all__'

class KeywordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Keyword
        fields = '__all__'

class SuggestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Suggestion
        fields = '__all__'

class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = '__all__'

class ActiveDomainSerializer(serializers.ModelSerializer):
    vuln_critical = serializers.IntegerField()
    vuln_high = serializers.IntegerField()
    vuln_medium = serializers.IntegerField()
    vuln_low = serializers.IntegerField()
    vuln_info = serializers.IntegerField()
    vulns = serializers.SerializerMethodField()

    class Meta:
        model = ActiveDomain
        fields = '__all__'

    def get_vulns(self, obj):
        return '<span class="label label-default">'+str(obj.vuln_critical)+'</span><span class="label label-danger">'+str(obj.vuln_high)+'</span><span class="label label-warning">'+str(obj.vuln_medium)+'</span><span class="label label-success">'+str(obj.vuln_low)+'</span><span  class="label label-primary">'+str(obj.vuln_info)+'</span>'

class FindingSerializer(serializers.ModelSerializer):
    asset = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = '__all__'

    def get_asset(self, obj):
        return obj.domain.value

class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = '__all__'

class ScreenshotSerializer(serializers.ModelSerializer):
    class Meta:
        model = Screenshot
        fields = '__all__'
        