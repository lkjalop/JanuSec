import os
try:
    import jwt
    print('jwt available')
    os.environ['JWT_SECRET']='test-jwt-secret'
    token = jwt.encode({'sub':'t','scopes':['factors.search']}, os.environ['JWT_SECRET'], algorithm='HS256')
    print('token sample', token)
    try:
        payload = jwt.decode(token, os.environ['JWT_SECRET'], algorithms=['HS256'], options={'verify_aud': False, 'verify_iss': False, 'verify_exp': False})
        print('decoded payload', payload)
    except Exception as e:
        print('decode failed', e)
except Exception:
    print('jwt not available')
