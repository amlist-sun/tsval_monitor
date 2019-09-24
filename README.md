# tsval_monitor
Linux utility for monitoring TS_Val on interface with libpcap.

To build utility run:
```
gcc -lpcap tsval_mon.c -o tsval_mon
```

To run the utility run:
```
sudo tsval_mon -i <interface> -p <period> /path/to/log
```
