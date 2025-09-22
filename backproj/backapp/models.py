from django.db import models
from django.contrib.auth.models import User

class MLJob(models.Model):
    job_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # link job to user
    text = models.TextField()           # input text for processing
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, default="pending")  # pending, processing, done
    result = models.TextField(null=True, blank=True)        # store result or JSON output

    def __str__(self):
        return f"Job {self.job_id} - {self.status}"
