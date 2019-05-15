import base64

def tob64(x):
    return base64.urlsafe_b64encode(x).decode('ascii').replace('=', '')

def fromb64(x):
    # ugly
    while len(x)%4!=0: x=x+'='
    return base64.urlsafe_b64decode(x.encode('ascii'))

def none_generator():
    while False: yield

def dictargs(**kwargs):
    return {k: v for k, v in kwargs.items() if v is not None}

def prepare_log():
    import logging
    logging.basicConfig()
    logging.getLogger('alias').setLevel(logging.DEBUG)
    #logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)

