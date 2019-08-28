from setuptools import setup, find_packages

setup(
    name='vsdnagent',
    version='0.1',
    packages=find_packages(),
    url='https://github.com/fernnf/vsdnagent.git',
    license='APACHE 2',
    author='Fernando Farias',
    author_email='fernnf@gmail.com',
    description='',
    classifiers=[
        'Development Status :: 0.2 - Release',
        'License :: OSI Approved :: APACHE2 License',
        'Programming Language :: Python :: 3.6',
        'Topic :: SDN Develop :: Network Emulator',
    ],
    include_package_data = True,
    zip_safe = False
)