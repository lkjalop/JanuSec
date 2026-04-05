# PowerShell helper to run the Redis Streams consumer as a background job or scheduled task
$env:REDIS_URL = 'redis://127.0.0.1:6379/0'
$script = Join-Path $PSScriptRoot '..\redis_streams_consumer.py'
python $script
