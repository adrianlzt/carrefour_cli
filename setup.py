from setuptools import setup

setup(
    name='CarrefourCLI',
    version='0.1',
    py_modules=['carrefour'],
    install_requires=[
        'click',
        'requests',
    ],
    entry_points='''
        [console_scripts]
        carrefour=carrefour:main
    ''',
)
