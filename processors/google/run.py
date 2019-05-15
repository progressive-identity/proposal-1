from collections import OrderedDict
import base64
import datetime
import json
import lzma
import mimetypes
import os
import re

from dateutil import tz
from tqdm import tqdm

import alias_index

GOOGLE_PATH = '/alias/google/'
GOOGLE_PHOTOS_PATH = os.path.join(GOOGLE_PATH, 'root/Takeout/Google Photos')

RE_MEDIA_DATETIME = re.compile(r"^(?P<type>(IMG|VID))[_-](?P<year>[0-9]{4})(?P<month>[0-9]{2})(?P<day>[0-9]{2})[_-]((?P<hour>[0-9]{2})(?P<minute>[0-9]{2})(?P<second>[0-9]{2}))?")
RE_PARENTDIR_DATE = re.compile(r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})")

def progress(desc):
    def decorator(func):
        from functools import wraps
        @wraps(desc)
        def wrapper(*kargs, **kwargs):
            it = func(*kargs, **kwargs)
            it = tqdm(it, desc)
            return it
        return wrapper
    return decorator

@progress("browsing files")
def walk_files(path):
    for path, dirs, fns in os.walk(path):
        for fn in fns:
            yield os.path.join(path, fn)

@progress("browsing Google Photos")
def walk_photos():
    for fpath in walk_files(GOOGLE_PHOTOS_PATH):
        mime, encoding = mimetypes.guess_type(fpath)

        if not mime:
            continue

        if not mime.startswith('image/') and not mime.startswith('video/'):
            continue

        try:
            with open(fpath + '.json', 'r') as fh:
                meta = json.load(fh)
        except FileNotFoundError:
            meta = None

        yield fpath, mime, meta

def photos():
    for fpath, mime, meta_json in walk_photos():
        meta = OrderedDict()

        fname = os.path.basename(fpath)

        meta['type'] = mime.split('/', 1)[0]

        m = RE_MEDIA_DATETIME.match(fname)
        if not m:
            dirname = os.path.basename(os.path.dirname(fpath))
            m = RE_PARENTDIR_DATE.match(dirname)

        if m:
            m = m.groupdict()

            if m.get('hour') is not None:
                # XXX UTC-0?
                meta['date'] = datetime.datetime(
                    year=int(m['year']),
                    month=int(m['month']),
                    day=int(m['day']),
                    hour=int(m['hour']),
                    minute=int(m['minute']),
                    second=int(m['second'])
                )

            else:
                meta['date'] = datetime.date(
                    year=int(m['year']),
                    month=int(m['month']),
                    day=int(m['day'])
                )

        if meta_json and 'geoData' in meta_json:
            geo = (meta_json['geoData']['longitude'], meta_json['geoData']['latitude'])

            if geo[0] != 0.0 and geo[1] != 0.0:
                meta['long'] = geo[0]
                meta['lat'] = geo[1]

        meta['full_image'] = alias_index.File(fpath, "sha256")

        yield meta


def generator():
    for v in photos():
        yield "google.photo", v

alias_index.dump(GOOGLE_PATH, generator())

