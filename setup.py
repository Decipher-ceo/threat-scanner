from setuptools import setup, find_packages

setup(
    name="phishing_line",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "flask==2.3.3",
        "flask-cors==3.0.10",
        "sqlalchemy==2.0.21",
        "apscheduler==3.10.1",
        "python-dateutil==2.8.2",
        "tldextract==3.4.0",
        "whois==0.9.27",
        "dnspython==2.3.0",
        "requests==2.31.0",
        "itsdangerous==2.1.2",
        "python-dotenv==1.0.0",
    ],
    python_requires=">=3.7",
)
