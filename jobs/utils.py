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
    job.output = ''
    job.save()
    try:
        process = subprocess.Popen(
            ['python3', '-u', 'manage.py', job.command] + job.args.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        output_lines = []
        for line in process.stdout:
            output_lines.append(line)
            job.output = ''.join(output_lines)
            job.save(update_fields=['output'])
        process.stdout.close()
        process.wait()
        # Defensive: ensure all output is captured
        if process.returncode == 0:
            job.status = 'finished'
        else:
            job.status = 'failed'
    except Exception as e:
        job.output = (job.output or '') + f"\nError: {e}"
        job.status = 'failed'
    finally:
        job.finished_at = now()
        job.save()
