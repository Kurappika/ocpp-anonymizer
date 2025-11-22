from setuptools import setup, find_packages

setup(
    name='ocpp-anonymizer',
    version='0.1.0',
    description='Deterministic PII Redaction for OCPP 1.6 logs.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/YourUsername/ocpp-anonymizer',
    license='MIT',
    # Automatically find all packages in the 'src' directory
    packages=find_packages(where='src'), 
    package_dir={'': 'src'},
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='ocpp pii privacy gdpr anonymization e-mobility',
    # Your project currently has no external dependencies beyond the standard library!
    install_requires=[], 
    python_requires='>=3.8',
)