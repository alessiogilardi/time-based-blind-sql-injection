# Time-Based-Blind-SQL-Injection Tool

This tool lets the user test security of a web application with respect to Time Based Blind SQL Injection and to exploit the vulnerability.

The tool takes in input an URL, a method, a list of possibly vulnerable fields with the respctive values.
Once found, the tool ask the user to select a database and a table to dump, after it prints the results.

```
usage: time_based_blind_sql_injection.py [-h] [-u URL] [-d DATA]
                                         [-m <GET|POST>] [-s SLEEP]
                                         [-t THREADS] [-v] [-l]

Tool used to perform time based blind sql injection

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     The URL on which try the attack.
  -d DATA, --data DATA  Payload for data fields. {'<field>': '<value>',...}
  -m <GET|POST>, --method <GET|POST>
                        The method <GET|POST>.
  -s SLEEP, --sleep SLEEP
                        The sleep time to use
  -t THREADS, --threads THREADS
                        Number of threads used for evaluating response time
  -v, --verbose         Set verbose mode
  -l, --log             Set log mode

```
