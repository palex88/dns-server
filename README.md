# dns-server

This is basic DNS server implementation that sends a dummy ip address back for queries on my github.io page. The IP address returned by the DNS query is for the broadcast channel, `255.255.255.255`.

Usage: 
* Start DNS server in a terminal window.
    * `sudo python dns.py`
    * Binding a socket to port 53 requires `sudo` since it is reserved for DNS.
* In another window, query my github.io page.
    * `dig palex88.github.io @127.0.0.1`
    
Using `dig` will return the ip address that the DNS server says the domain is located at. 
    
Notes:
* Written in Python3, probably wont work in Python2.
* Running on port `53`, at IP address `127.0.0.1`.


[The RFC for DNS can be found here.](https://www.ietf.org/rfc/rfc1035.txt)