Abandoned, there are better tools for the job out there.

# urly

URLY is a nifty little python tool used to pull threat intelligence on IOCs.
Currently has support for IP address via ipvoid and domains via urlvoid with
dynamic input detection, so you don't have to tell the app what you're feeding!

Requires:
- tld
- bs4
- dnspython?

TODO:
- local caching
- more intel sources - VT, Google Safe Browsing etc.
- bulk processing
- output to file
- stdout formatting
- config file for API details
- API key detection to decide which feeds to use at runtime
- input as PCAP - carve all IP address
