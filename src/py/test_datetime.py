import datetime
import contextlib

import utils


class context:
    def __init__(self):
        self.enabled = False

    def set(self, x):
        self.value = x
        return self

    def add(self, **kwargs):
        self.value = self.value + datetime.timedelta(**kwargs)
        return self


ctx = context()


@contextlib.contextmanager
def debug(x=None):
    ctx.value = x or datetime.datetime.utcnow()
    ctx.enabled = True
    yield ctx
    ctx.enabled = False


def delta(**kwargs):
    if not kwargs:
        kwargs['days'] = 1
    td = datetime.timedelta(**kwargs)

    return debug(datetime.datetime.utcnow() + td)


def past():
    return debug(datetime.datetime.utcfromtimestamp(0))


def future():
    return delta(days=1000 * 365.25)


def patched_utcnow():
    if ctx.enabled:
        return ctx.value

    else:
        return datetime.datetime.utcnow()


def patch():
    utils.utcnow = patched_utcnow
