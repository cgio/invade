import setuptools

version = {}
with open('invade/version.py') as fp:
    exec(fp.read(), version)

with open('README.md', 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='invade',
    version=version['__version__'],
    author='Chad Gosselin',
    description='A library for interacting with Windows process memory',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/cgio/invade',
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
    install_requires=[
          'pefile',
    ],
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Security',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research'
    ],
)
