# Time-Based-Blind-SQL-Injection Tool

This tool lets the user test security of a web application with respect to Time Based Blind SQL Injection and to exploit the vulnerability.

The tool takes in input an URL, a method, a list of possibly vulnerable fields with the respctive values.
Once found, the tool ask the user to select a database and a table to dump, after it prints the results.

```
usage: time_based_blind_sql_injection.py [-h] [-u URL] [-d {'<field>': '<value>',...}] [-m <GET|POST>] [-s SLEEP] [-t THREADS] [-v] [-l]
  
positional arguments:
  <url>                 The URL on which try the attack.
  <GET|POST>            The method [GET|POST]
  <fields>              The fields: ['field1','field2','field3'],...
  <values>              The values: ['value1','value2','value3'],...

optional arguments:
  -h, --help            show this help message and exit
  -s SLEEP, --sleep SLEEP
                        The sleep time to use
  -t THREADS, --threads THREADS
                        Number of threads used for evaluating response time
  -v, --verbose         Set verbose mode
  -l, --log             Set log mode
```
