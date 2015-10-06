import os
import re
from setuptools import setup

MODULE_NAME = 'scalable_admin'

README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()
VERSION = re.search("__version__ = '([^']+)'",
                    open('{0}.py'.format(MODULE_NAME)).read()).group(1)

setup(name=MODULE_NAME,
      author='Bryce Boe',
      author_email='bbzbryce@gmail.com',
      classifiers=['Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python'],
      description=('A command line tool to facilitate the administration of '
                   'the scalable Internet services course taught at UCSB and '
                   'UCLA.'),
      entry_points={'console_scripts': ['{0} = {0}:main'.format(MODULE_NAME)]},
      install_requires=['docopt >=0.6.2, <1',
                        'github3.py >=1.0.0a2, <1.0.1'],
      keywords=['course administration', 'cloud formation templates', 'aws',
                'github'],
      license='Simplified BSD License',
      long_description=README,
      py_modules=[MODULE_NAME],
      url = 'https://github.com/scalableinternetservices/utils',
      version=VERSION)
