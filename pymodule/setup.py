import setuptools

with open("README.md") as fh:
    long_description=fh.read()

setuptools.setup(
    name='walataint',
    version='0.0.2',
    author='anemone',
    author_email='anemone95@qq.com',
    description='Primitive package for walataint',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Anemone95/wala-taint/',
    packages=setuptools.find_packages(where='src'),
    package_dir={"":"src"},
    license='',
)
