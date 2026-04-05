import importlib
try:
    m = importlib.import_module('moto')
    print('moto module file:', getattr(m, '__file__', None))
    print('has mock_s3:', hasattr(m, 'mock_s3'))
    print('has mock_sqs:', hasattr(m, 'mock_sqs'))
    print('mock_s3:', getattr(m, 'mock_s3', None))
    print('mock_sqs:', getattr(m, 'mock_sqs', None))
except Exception as e:
    print('import moto failed:', e)
