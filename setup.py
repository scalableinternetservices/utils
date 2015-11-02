"""Scalable Admin package setup."""

import os
import re
from setuptools import setup

PACKAGE_NAME = 'scalable_admin'

HERE = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(HERE, 'README.md')) as fp:
    README = fp.read()
with open(os.path.join(HERE, PACKAGE_NAME, '__init__.py')) as fp:
    VERSION = re.search("__version__ = '([^']+)'", fp.read()).group(1)

setup(name=PACKAGE_NAME,
      author='Bryce Boe',
      author_email='bbzbryce@gmail.com',
      classifiers=['Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python'],
      description=('A command line tool to facilitate the administration of '
                   'the scalable Internet services course taught at UCSB and '
                   'UCLA.'),
      entry_points={'console_scripts':
                    ['{0}={0}.command_line:main'.format(PACKAGE_NAME)]},
      install_requires=['botocore >=1.2, <1.4',
                        'docopt >=0.6.2, <1',
                        'github3.py >=1.0.0a2, <1.0.1'],
      keywords=['course administration', 'cloud formation templates', 'aws',
                'github'],
      license='Simplified BSD License',
      long_description=README,
      packages=[PACKAGE_NAME],
      package_data={PACKAGE_NAME: ['segments/*.sh']},
      url = 'https://github.com/scalableinternetservices/utils',
      version=VERSION)
