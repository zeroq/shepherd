import subprocess
import threading
from django.utils.timezone import now
from project.models import Job, Project

def run_job(command, args, projectid, user=None):
    job = Job()
    job.related_project = Project.objects.get(id=projectid)
    job.user = user
    job.status = 'running'
    job.started_at = now()
    job.command = command
    job.args = args
    job.save()
    try:
        process = subprocess.Popen(
            ['python3', '-u', 'manage.py', job.command] + job.args.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        output = ''
        for line in process.stdout:
            output += line
            job.output = output
            job.save(update_fields=['output'])
        process.wait()
        job.status = 'finished' if process.returncode == 0 else 'failed'
    except Exception as e:
        job.output += f"\nError: {e}"
        job.status = 'failed'
    job.finished_at = now()
    job.save()
